// Read-only SQLite access for the catalog readers.
//
// Several of these apps keep their cached model catalog in SQLite. The driver
// is `modernc.org/sqlite`, a pure-Go translation, so the plugin keeps building
// without CGO and cross-compiles to every DBX target from one machine.

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// queryTimeout bounds a catalog read; these are local files.
const queryTimeout = 8 * time.Second

// querySQLite runs a read-only query and returns the rows as strings.
//
// The connection is opened in read-only, query-only mode so a plugin read can
// never write to, lock, or migrate another application's database.
func querySQLite(path string, query string, args ...any) ([][]string, error) {
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)", path)
	return queryDSN(dsn, query, args...)
}

// querySQLiteImmutable opens the database with immutable=1, which tells SQLite
// the file will not change and lets it skip the WAL/-shm handshake. Some
// Chromium stores (Doubao's cookie DB) are WAL-mode and held by a running app,
// so a plain read-only open fails with SQLITE_CANTOPEN; immutable reads through
// that. It is a fallback only: a concurrent writer could expose a torn page, so
// callers use it just for best-effort identity reads, never for anything that
// must be transactionally consistent.
func querySQLiteImmutable(path string, query string, args ...any) ([][]string, error) {
	dsn := fmt.Sprintf("file:%s?immutable=1&_pragma=query_only(1)", path)
	return queryDSN(dsn, query, args...)
}

// queryDSN runs a read-only query against an already-formed SQLite DSN.
func queryDSN(dsn string, query string, args ...any) ([][]string, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := make([][]string, 0, 32)
	for rows.Next() {
		cells := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range cells {
			pointers[i] = &cells[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return nil, err
		}
		record := make([]string, len(columns))
		for i, cell := range cells {
			record[i] = stringifyCell(cell)
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

// stringifyCell renders a column value, including BLOBs, as text.
func stringifyCell(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return fmt.Sprint(typed)
	}
}

// jsonUnmarshal is a tiny indirection so source files do not each import
// encoding/json for one call.
func jsonUnmarshal(raw []byte, target any) error {
	return json.Unmarshal(raw, target)
}
