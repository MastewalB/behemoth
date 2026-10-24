package adapters

import "github.com/go-behemoth/behemoth/errs"

// SQLiteForeignKeysPragma is the statement that reports whether the
// connection enforces foreign keys: one row with 1 or 0.
const SQLiteForeignKeysPragma = "PRAGMA foreign_keys"

// SQLiteForeignKeysError returns nil when enabled is 1, the value of
// SQLiteForeignKeysPragma on an enforcing connection, and a configuration
// error for op otherwise. The error says how to open the database with
// foreign keys on, because SQLite starts every connection with them off.
func SQLiteForeignKeysError(op string, enabled int) error {
	if enabled == 1 {
		return nil
	}
	return errs.NewConfigurationError(op,
		"SQLite does not enforce foreign keys on this connection. Open the database with them on: "+
			"add _foreign_keys=on to the DSN of github.com/mattn/go-sqlite3 (file:app.db?_foreign_keys=on), "+
			"or _pragma=foreign_keys(1) for modernc.org/sqlite. "+
			"To run without them, set BootConfig.AllowUnenforcedForeignKeys",
		nil)
}
