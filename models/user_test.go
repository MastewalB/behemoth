package models

import (
	"reflect"
	"sort"
	"testing"
	"time"
)

// The column constants are the single source of the users table's names:
// ToMap must produce exactly them, and FromMap must read every one back.
func TestUserColumnsAreTheConstants(t *testing.T) {
	want := []string{UserID, UserEmail, UserUsername, UserFirstname, UserLastname,
		UserPasswordHash, UserEmailVerified, UserImageURL, UserCreatedAt, UserUpdatedAt}
	row, err := (&User{}).ToMap()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for k := range row {
		got = append(got, k)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ToMap columns = %v, want %v", got, want)
	}
	if (&User{}).SchemaName() != UserTable || (&User{}).PrimaryKeyName() != UserID {
		t.Error("SchemaName / PrimaryKeyName must be the constants")
	}
}

func TestUserRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	in := &User{ID: "u1", Email: "a@example.com", Username: "a", Firstname: "A", Lastname: "B",
		PasswordHash: "h", EmailVerified: true, ImageUrl: "i", CreatedAt: now, UpdatedAt: now}
	row, err := in.ToMap()
	if err != nil {
		t.Fatal(err)
	}
	out := &User{}
	if err := out.FromMap(row); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip:\n got  %+v\n want %+v", out, in)
	}
}
