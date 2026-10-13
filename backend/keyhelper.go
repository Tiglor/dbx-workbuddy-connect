// Credential discovery and at-rest key retrieval for the WorkBuddy desktop app.
//
// The at-rest protector key cannot be read from any file: WorkBuddy keeps it in
// an Electron private binding (`electron_browser_workbuddy_storage`) and only
// exposes it to its own executable. The supported way to obtain it — the same
// mechanism the reference DSH plugin uses — is to run the installed WorkBuddy
// binary once with a helper script that prints the binding's value as JSON.
//
// This is why the plugin needs a native sidecar at all: a sandboxed workbench
// UI cannot spawn a process or read credentials off disk.

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// helperScript prints the at-rest payload; it is passed via `-e`.
	helperScript = `process.stdout.write(String(process._linkedBinding("electron_browser_workbuddy_storage").loggerGet()))`

	// helperTimeout bounds the spawn; WorkBuddy cold start can be slow.
	helperTimeout = 45 * time.Second

	// envElectronBin lets a user point at a non-standard install.
	// Mirrors the reference plugin's WORKBUDDY_ELECTRON_BIN.
	envElectronBin = "WORKBUDDY_ELECTRON_BIN"

	// authDirSegments is the shared CodeBuddy auth directory (CN + intl apps
	// share the directory and differ only by filename).
	authDirSegments = "CodeBuddyExtension/Data/Public/auth"

	cnAuthFilename = "workbuddy-desktop.info"
	cnExeBasename  = "WorkBuddy.exe"
)

// atRestPayload is the helper's JSON answer.
type atRestPayload struct {
	Version         int    `json:"version"`
	AtRestSecretKey string `json:"atRestSecretKey"`
}

// parseAtRestPayload validates the helper output. The reference implementation
// requires version 1 and a canonical, non-zero 32-byte base64 secret.
func parseAtRestPayload(text string) (string, error) {
	var payload atRestPayload
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		return "", errors.New("WorkBuddy key helper returned no usable at-rest payload (expected {version:1, atRestSecretKey})")
	}
	if payload.Version != 1 || payload.AtRestSecretKey == "" {
		return "", errors.New("WorkBuddy key helper returned no usable at-rest payload (expected {version:1, atRestSecretKey})")
	}
	decoded, err := base64.StdEncoding.DecodeString(payload.AtRestSecretKey)
	if err != nil || len(decoded) != 32 {
		return "", errors.New("WorkBuddy at-rest secret is not a 32-byte base64 value")
	}
	allZero := true
	for _, b := range decoded {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "", errors.New("WorkBuddy at-rest secret is empty")
	}
	return payload.AtRestSecretKey, nil
}

// desktopAuthCandidates lists the credential files to probe, in order.
func desktopAuthCandidates() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	switch runtime.GOOS {
	case "darwin":
		return []string{filepath.Join(home, "Library", "Application Support", filepath.FromSlash(authDirSegments), cnAuthFilename)}
	case "windows":
		var out []string
		for _, root := range []string{os.Getenv("LOCALAPPDATA"), os.Getenv("APPDATA")} {
			if root == "" {
				continue
			}
			out = append(out, filepath.Join(root, filepath.FromSlash(authDirSegments), cnAuthFilename))
		}
		return out
	default:
		var out []string
		for _, root := range []string{os.Getenv("XDG_CONFIG_HOME"), os.Getenv("XDG_DATA_HOME")} {
			if root == "" {
				continue
			}
			out = append(out, filepath.Join(root, filepath.FromSlash(authDirSegments), cnAuthFilename))
		}
		return out
	}
}

// electronCandidates lists plausible WorkBuddy executable locations.
//
// The reference plugin discovers the app through Windows uninstall records with
// a strict layout check, and misses the very common per-user install under
// %LOCALAPPDATA%\Programs. This walks the known roots and validates the layout
// (the executable next to a `resources` directory) instead, which covers both.
func electronCandidates() []string {
	var candidates []string
	add := func(p string) {
		if p == "" {
			return
		}
		for _, existing := range candidates {
			if strings.EqualFold(existing, p) {
				return
			}
		}
		candidates = append(candidates, p)
	}

	if explicit := os.Getenv(envElectronBin); explicit != "" {
		// An explicit path is authoritative and never falls back.
		return []string{explicit}
	}

	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		var roots []string
		if local := os.Getenv("LOCALAPPDATA"); local != "" {
			roots = append(roots,
				filepath.Join(local, "Programs", "WorkBuddy"),
				filepath.Join(local, "WorkBuddy"),
			)
		}
		if pf := os.Getenv("ProgramFiles"); pf != "" {
			roots = append(roots, filepath.Join(pf, "WorkBuddy"))
		}
		if pf86 := os.Getenv("ProgramFiles(x86)"); pf86 != "" {
			roots = append(roots, filepath.Join(pf86, "WorkBuddy"))
		}
		for _, root := range roots {
			add(filepath.Join(root, cnExeBasename))
		}
	case "darwin":
		add("/Applications/WorkBuddy.app/Contents/MacOS/WorkBuddy")
		add(filepath.Join(home, "Applications", "WorkBuddy.app", "Contents", "MacOS", "WorkBuddy"))
	}
	return candidates
}

// resolveElectronPath returns the first candidate that exists and looks like an
// Electron app (executable beside a resources directory, or an .app bundle).
func resolveElectronPath() (string, error) {
	candidates := electronCandidates()
	if len(candidates) == 0 {
		return "", errors.New("no WorkBuddy installation path is known for this platform; set " + envElectronBin + " to the WorkBuddy executable")
	}
	if len(candidates) == 1 && os.Getenv(envElectronBin) != "" {
		if _, err := os.Stat(candidates[0]); err != nil {
			return "", fmt.Errorf("%s points at %s, which cannot be read: %w", envElectronBin, candidates[0], err)
		}
		return candidates[0], nil
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		if looksLikeElectronApp(candidate) {
			return candidate, nil
		}
	}
	return "", errors.New("no WorkBuddy application was found; if it is installed elsewhere, set " + envElectronBin + " to its executable")
}

// looksLikeElectronApp checks for the Electron layout rather than trusting a
// registry entry (the reference plugin makes the same distinction).
func looksLikeElectronApp(exe string) bool {
	dir := filepath.Dir(exe)
	if _, err := os.Stat(filepath.Join(dir, "resources")); err == nil {
		return true
	}
	// macOS: .../WorkBuddy.app/Contents/MacOS/WorkBuddy -> .../Contents/Resources
	if strings.Contains(dir, string(filepath.Separator)+"MacOS") {
		if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "Resources")); err == nil {
			return true
		}
	}
	return false
}

// fetchAtRestSecretKey runs the WorkBuddy binary once and returns the raw secret
// string (the SHA-256 input), never the derived key.
func fetchAtRestSecretKey(ctx context.Context) (string, error) {
	exe, err := resolveElectronPath()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, helperTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, exe, "-e", helperScript)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Keep the child from opening a window or inheriting a console.
	cmd.Env = append(os.Environ(),
		"ELECTRON_RUN_AS_NODE=1",
		"WORKBUDDY_HELPER=1",
	)

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("reading the WorkBuddy at-rest key timed out after %s", helperTimeout)
		}
		detail := trimSpace(stderr.String())
		if len(detail) > 300 {
			detail = detail[:300]
		}
		if detail == "" {
			return "", fmt.Errorf("could not run %s to read the WorkBuddy at-rest key", exe)
		}
		return "", fmt.Errorf("WorkBuddy key helper failed: %s", detail)
	}
	return parseAtRestPayload(stdout.String())
}
