package models

import "testing"

func TestExtrasRoundTrip(t *testing.T) {
	in := &User{ID: "u1", Email: "a@example.com"}
	in.SetExtra("plan", "pro")
	in.SetExtra(UserEmail, "must-not-win@example.com") // an extra can't shadow an own column

	row, err := in.ToMap()
	if err != nil {
		t.Fatal(err)
	}
	if row["plan"] != "pro" {
		t.Errorf("ToMap dropped the extra: %v", row)
	}
	if row[UserEmail] != "a@example.com" {
		t.Errorf("an extra overwrote an own column: %v", row[UserEmail])
	}

	out := &User{}
	if err := out.FromMap(row); err != nil {
		t.Fatal(err)
	}
	if out.Extras()["plan"] != "pro" || len(out.Extras()) != 1 {
		t.Errorf("FromMap extras = %v, want only plan", out.Extras())
	}
	if out.Email != "a@example.com" {
		t.Errorf("own column read as %q", out.Email)
	}

	// FromMap replaces extras rather than accumulating them.
	if err := out.FromMap(map[string]any{UserID: "u1"}); err != nil {
		t.Fatal(err)
	}
	if len(out.Extras()) != 0 {
		t.Errorf("stale extras kept: %v", out.Extras())
	}
}
