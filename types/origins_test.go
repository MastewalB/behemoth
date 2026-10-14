package types

import "testing"

func TestTrustedOrigins(t *testing.T) {
	for _, bad := range []string{"app.example.com", "ftp://app.example.com", "https://app.example.com/path", "https://user@app.example.com", "https://app.example.com?x=1", "https://"} {
		if _, err := NewTrustedOrigins([]string{bad}); err == nil {
			t.Errorf("NewTrustedOrigins(%q) = nil error, want it refused", bad)
		}
	}

	origins, err := NewTrustedOrigins([]string{"https://App.example.com", "http://localhost:3000/", "https://[::1]:8443"})
	if err != nil {
		t.Fatal(err)
	}
	for origin, want := range map[string]bool{
		"https://app.example.com":      true,
		"https://APP.example.com:443":  true,
		"http://localhost:3000":        true,
		"https://[::1]:8443":           true,
		"http://app.example.com":       false, // another scheme
		"https://app.example.com:8443": false, // another port
		"https://evil.example.com":     false,
		"https://app.example.com.evil": false,
		"https://app.example.com/path": false, // not an origin
		"":                             false,
	} {
		if got := origins.IsTrusted(origin); got != want {
			t.Errorf("IsTrusted(%q) = %v, want %v", origin, got, want)
		}
	}
	if (*TrustedOrigins)(nil).IsTrusted("https://app.example.com") {
		t.Error("a nil validator trusted an origin")
	}

	for target, want := range map[string]bool{
		"/dashboard":                           true,
		"/dashboard?tab=1#top":                 true,
		"https://app.example.com/welcome?a=b":  true,
		"http://localhost:3000/":               true,
		"":                                     false,
		"dashboard":                            false, // relative to the current page
		"//evil.example.com/x":                 false,
		"/\\evil.example.com":                  false,
		"https://evil.example.com/":            false,
		"https://app.example.com@evil.example": false,
		"https://user@app.example.com/":        false,
		"javascript:alert(1)":                  false,
		"https://app.example.com\n/x":          false,
	} {
		if got := TrustedRedirect(origins, target); got != want {
			t.Errorf("TrustedRedirect(%q) = %v, want %v", target, got, want)
		}
	}
	if !TrustedRedirect(nil, "/dashboard") || TrustedRedirect(nil, "https://app.example.com/") {
		t.Error("without a validator only paths pass")
	}
}
