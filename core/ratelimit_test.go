package core

import (
	"context"
	"testing"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/identity"
)

// KeyByValues joins the named Values entries, and says the rule does not
// apply when one of them is missing or empty.
func TestKeyByValues(t *testing.T) {
	keyFunc := KeyByValues("kind", "subject")
	for name, tc := range map[string]struct {
		values behemoth.M
		key    string
		ok     bool
	}{
		"both set":        {behemoth.M{"kind": "invite", "subject": "team-1"}, "invite|team-1", true},
		"not a string":    {behemoth.M{"kind": "invite", "subject": 42}, "invite|42", true},
		"one missing":     {behemoth.M{"kind": "invite"}, "", false},
		"one empty":       {behemoth.M{"kind": "invite", "subject": ""}, "", false},
		"one nil":         {behemoth.M{"kind": "invite", "subject": nil}, "", false},
		"no values":       {nil, "", false},
		"other keys only": {behemoth.M{"email": "ada@example.com"}, "", false},
	} {
		key, ok := keyFunc(&HookContext{Values: tc.values})
		if key != tc.key || ok != tc.ok {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", name, key, ok, tc.key, tc.ok)
		}
	}

	if key, ok := KeyByValues()(&HookContext{}); key != "" || !ok {
		t.Errorf("no keys: got (%q, %v), want an empty key that applies", key, ok)
	}
}

// KeyByClientIP keys on the caller's address, then on the named Values
// entries, and says the rule does not apply to a caller without an address
// or to a call without one of the entries.
func TestKeyByClientIP(t *testing.T) {
	withAddress := identity.WithCaller(context.Background(), identity.Anonymous(identity.Peer{Transport: "http", IPAddress: "203.0.113.7"}))
	job := identity.WithCaller(context.Background(), identity.System("job"))
	for name, tc := range map[string]struct {
		keyFunc func(*HookContext) (string, bool)
		ctx     context.Context
		values  behemoth.M
		key     string
		ok      bool
	}{
		"the address":               {KeyByClientIP(), withAddress, nil, "203.0.113.7", true},
		"the address and the value": {KeyByClientIP("method"), withAddress, behemoth.M{"method": "magiclink"}, "203.0.113.7|magiclink", true},
		"the value missing":         {KeyByClientIP("method"), withAddress, behemoth.M{}, "", false},
		"no address":                {KeyByClientIP(), job, nil, "", false},
		"no caller":                 {KeyByClientIP("method"), context.Background(), behemoth.M{"method": "magiclink"}, "", false},
	} {
		key, ok := tc.keyFunc(&HookContext{Ctx: tc.ctx, Values: tc.values})
		if key != tc.key || ok != tc.ok {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", name, key, ok, tc.key, tc.ok)
		}
	}
}
