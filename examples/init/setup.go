package main

import (
	"database/sql"
	"os"

	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/plugins/emailpassword"
	"github.com/MastewalB/behemoth/plugins/magiclink"
	"github.com/MastewalB/behemoth/types"
	bmth "github.com/MastewalB/behemoth/types/init"
	_ "github.com/lib/pq"
)

// Everything below is shared by both commands, so `migrate` and `serve`
// always see the same plugins, the same schema and therefore the same
// SchemaResolver.

// plugins returns the plugin list for Prepare. The email/password plugin is
// returned a second time by its own type, because the signup command calls
// its SignUp and SignIn methods directly.
//
// Two of them mail a link, and each is told which page of the application
// its link opens (pages.go). The messages go to the sender in BootConfig.Mail
// (mail.go).
func plugins() ([]types.Plugin, *emailpassword.Plugin) {
	ep := emailpassword.New(emailpassword.Options{
		// Setting the link URL is what turns password reset on.
		Reset: emailpassword.ResetOptions{LinkURL: appURL() + pathResetPage},
	})
	// Sign-in by a mailed link, next to sign-in by password. A user created
	// by either plugin can use both.
	ml := magiclink.New(magiclink.Options{LinkURL: appURL() + pathMagicPage})
	return []types.Plugin{ep, ml, &ActivityPlugin{}}, ep
}

func prepareConfig() bmth.PrepareConfig {
	return bmth.PrepareConfig{
		Migration: core.MigrationConfig{
			FolderPath: "migrations",
			// Path is left empty: PathGenerateOnly, behemoth writes files
			// and never touches the database schema on its own.
		},
		Schema: declareAppSchema,
	}
}

func openDB() (*sql.DB, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/behemoth?sslmode=disable"
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	return db, db.Ping()
}
