module github.com/workbuddy-community/dbx-workbuddy-connect

go 1.26.0

require (
	github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk v0.1.0
	modernc.org/sqlite v1.60.1
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.48.0 // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

// The SDK is vendored into this repository so the plugin builds reproducibly
// from a clean clone (CI and store review included). dbx-plugin create writes
// an absolute path to the local CLI's sdk-root here; that path does not exist
// on any other machine, so it must never be committed.
replace github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk => ./dbx-plugin-sdk
