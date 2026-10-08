package types

import (
	"testing"

	"github.com/MastewalB/behemoth"
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
