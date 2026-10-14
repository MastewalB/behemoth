package telemetry

import (
	"strings"

	"github.com/MastewalB/behemoth"
)

// Redacted replaces the value of a redacted log field.
const Redacted = "[REDACTED]"

// redactedKeys are the field keys whose values never reach a log backend.
// A key matches when, lowercased, it equals one of these or ends with it:
// "password", "newPassword" and "refresh_token" match, "tokenID" does not.
var redactedKeys = []string{"password", "token", "secret", "hash", "cookie", "authorization"}

// emailKey is redacted unless WithEmailsInLogs is set. Logs carry user IDs
// by default; the audit log is where an email is recorded.
const emailKey = "email"

type redactor struct {
	keys []string
}

func newRedactor(o options) redactor {
	keys := append([]string{}, redactedKeys...)
	if !o.allowEmails {
		keys = append(keys, emailKey)
	}
	for _, k := range o.extraKeys {
		if k != "" {
			keys = append(keys, strings.ToLower(k))
		}
	}
	return redactor{keys: keys}
}

func (r redactor) matches(key string) bool {
	key = strings.ToLower(key)
	for _, k := range r.keys {
		if strings.HasSuffix(key, k) {
			return true
		}
	}
	return false
}

// redact returns a copy of fields with the value of every matching key
// replaced by Redacted. Nested maps are redacted the same way. The caller's
// map is not changed. Matching is by key only: a secret placed in a message
// or under an unrelated key is not detected.
func (r redactor) redact(fields behemoth.M) behemoth.M {
	if fields == nil {
		return nil
	}
	out := make(behemoth.M, len(fields))
	for k, v := range fields {
		switch {
		case r.matches(k):
			out[k] = Redacted
		default:
			out[k] = r.redactValue(v)
		}
	}
	return out
}

func (r redactor) redactValue(v any) any {
	switch m := v.(type) {
	case behemoth.M:
		return r.redact(m)
	case map[string]any:
		return map[string]any(r.redact(m))
	}
	return v
}

// Redact returns a copy of fields as a Logger built by New with opts would
// pass them to its backend. It is for code that writes fields somewhere
// other than a Logger and wants the same rules.
func Redact(fields behemoth.M, opts ...Option) behemoth.M {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return newRedactor(o).redact(fields)
}
