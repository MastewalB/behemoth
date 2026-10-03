package models

import (
	"reflect"
	"testing"
	"time"
)

func TestAccountRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)
	in := &Account{ID: "a1", UserID: "u1", ProviderID: "google", AccountID: "g-123",
		AccessToken: "at", RefreshToken: "rt", IDToken: "it", AccessTokenExpiresAt: &expires,
		Scope: "openid", CreatedAt: now, UpdatedAt: now}
	row, err := in.ToMap()
	if err != nil {
		t.Fatal(err)
	}
	if row[AccountPasswordHash] != nil || row[AccountRefreshTokenExpiresAt] != nil {
		t.Errorf("absent values must be stored as NULL: %v", row)
	}
	out := &Account{}
	if err := out.FromMap(row); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip:\n got  %+v\n want %+v", out, in)
	}
}
