// Self-check mode: exercise the plugin's own code paths from a command line so
// a build can be verified without DBX.
//
// Invoked as: <sidecar> --status | --sources | --models | --credits

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func runSelfCheck(mode string) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	plugin := newPlugin(dataDirFromEnv())

	fail := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
		os.Exit(2)
	}

	switch mode {
	case "--status":
		path, format, _ := plugin.store.resolvedDesktopAuthPath()
		electron, electronErr := resolveElectronPath()
		printJSON(map[string]any{
			"auth":          plugin.store.status(ctx),
			"desktopAuth":   path,
			"authFormat":    format,
			"electron":      electron,
			"electronError": errorText(electronErr),
			"dataDir":       dataDirFromEnv(),
		})

	case "--sources":
		// Every configured source, whether or not it can serve chat.
		statuses := make([]map[string]any, 0, len(plugin.sources))
		for _, source := range plugin.sources {
			status := source.Status(ctx)
			entry := map[string]any{
				"id":        status.ID,
				"name":      status.Name,
				"installed": status.Installed,
				"callable":  status.Callable,
				"state":     status.State,
				"detail":    status.Detail,
			}
			if status.CredentialPath != "" {
				entry["credentialPath"] = status.CredentialPath
			}
			if status.AppPath != "" {
				entry["appPath"] = status.AppPath
			}
			if rows, err := source.Models(ctx); err != nil {
				entry["modelError"] = err.Error()
			} else {
				entry["modelCount"] = len(rows)
			}
			statuses = append(statuses, entry)
		}
		printJSON(map[string]any{"sources": statuses})

	case "--models":
		_, rows, warnings := mergeSources(ctx, plugin.sources)
		bySource := map[string][]string{}
		for _, row := range rows {
			bySource[row.Source] = append(bySource[row.Source], row.RemoteID)
		}
		printJSON(map[string]any{
			"total":    len(rows),
			"bySource": bySource,
			"warnings": warnings,
		})

	case "--credits":
		cred, err := plugin.store.resolve(ctx)
		if err != nil {
			fail("credential: %v", err)
		}
		summary, err := plugin.client.fetchCredits(ctx, cred)
		if err != nil {
			fail("credits: %v", err)
		}
		active := 0
		for _, entry := range summary.Accounts {
			if entry.Remain > 0 {
				active++
			}
		}
		printJSON(map[string]any{
			"total":          summary.Total,
			"packages":       len(summary.Accounts),
			"activePackages": active,
			"enterprise":     cred.EnterpriseID != "",
		})

	default:
		fail("unknown self-check mode %q; use --status, --sources, --models or --credits", mode)
	}
}

func printJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
