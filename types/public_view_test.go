package types

import (
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/types/schema"
)

// The view of a user has the table's public columns and the contributed
// columns their declarer marked Public, flat and in their declared types.
// A private column is left out whether it is contributed or the table's
// own, and a table nobody declared has no view.
func TestPublicView(t *testing.T) {
	registry := schema.NewRegistry()
	if err := registry.Declare(&models.User{}, models.UserTableSchema()); err != nil {
		t.Fatal(err)
	}
	if err := registry.Declare(&models.Session{}, models.SessionTableSchema()); err != nil {
		t.Fatal(err)
	}
	for _, c := range []schema.Column{
		{Name: "plan", Type: schema.ColTypeString, Public: true},
		{Name: "beta", Type: schema.ColTypeBoolean, Public: true},
		{Name: "unset", Type: schema.ColTypeString, Nullable: true, Public: true},
		{Name: "risk_note", Type: schema.ColTypeText}, // private: the default
	} {
		if err := registry.ExtendColumn(schema.ColumnContribution{Table: models.UserTable, Column: c, Owner: "billing"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := registry.Freeze(); err != nil {
		t.Fatal(err)
	}
	view := NewPublicView(registry.All())

	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	user := &models.User{ID: "u1", Email: "ada@example.com", Firstname: "Ada", EmailVerified: true, CreatedAt: at, UpdatedAt: at}
	// As a driver returns them: SQLite's 1 for true, bytes for text.
	user.SetExtra("plan", []byte("pro"))
	user.SetExtra("beta", int64(1))
	user.SetExtra("unset", nil)
	user.SetExtra("risk_note", "flagged")
	user.SetExtra("undeclared", "a column no one declared")

	got, err := view.Of(user)
	if err != nil {
		t.Fatal(err)
	}
	want := behemoth.M{
		"id": "u1", "email": "ada@example.com", "username": "", "firstname": "Ada", "lastname": "",
		"email_verified": true, "image_url": "", "created_at": at, "updated_at": at,
		"plan": "pro", "beta": true, "unset": nil,
	}
	if len(got) != len(want) {
		t.Errorf("view has %d columns, want %d: %v", len(got), len(want), got)
	}
	for k, w := range want {
		if g, ok := got[k]; !ok || g != w {
			t.Errorf("%s = %#v (present %v), want %#v", k, g, ok, w)
		}
	}
	for _, private := range []string{"risk_note", "undeclared", "extra"} {
		if _, ok := got[private]; ok {
			t.Errorf("the view has %q", private)
		}
	}

	// A declared table with no public column: an empty view, not an error.
	session, err := view.Of(&models.Session{ID: "s1", UserID: "u1", TokenHash: "secret"})
	if err != nil || len(session) != 0 {
		t.Errorf("view of a session = %v, %v; want empty: sessions declare nothing public", session, err)
	}

	for name, m := range map[string]behemoth.Model{"an undeclared table": &models.Token{}, "no model": nil} {
		if _, err := view.Of(m); !behemotherr.Is(err, behemotherr.CategoryConfiguration) {
			t.Errorf("%s: Of returned %v, want a configuration error", name, err)
		}
	}
}
