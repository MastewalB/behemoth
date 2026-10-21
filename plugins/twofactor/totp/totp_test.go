package totp

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// rfcSecret is the secret of the test vectors in RFC 4226 and RFC 6238 for
// SHA-1: the ASCII bytes of "12345678901234567890".
var rfcSecret = []byte("12345678901234567890")

// The HOTP values of RFC 4226, appendix D, for counters 0 to 9. A counter is
// a time step here, so the code of step c is the code at c periods.
func TestCodeMatchesRFC4226(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for counter, code := range want {
		at := time.Unix(int64(counter)*int64(Period/time.Second), 0)
		if got := Code(rfcSecret, at); got != code {
			t.Errorf("counter %d: Code = %s, want %s", counter, got, code)
		}
	}
}

// The SHA-1 rows of RFC 6238, appendix B. The RFC's codes have eight digits;
// a six-digit code is their last six.
func TestCodeMatchesRFC6238(t *testing.T) {
	for unix, eight := range map[int64]string{
		59:          "94287082",
		1111111109:  "07081804",
		1111111111:  "14050471",
		1234567890:  "89005924",
		2000000000:  "69279037",
		20000000000: "65353130",
	} {
		want := eight[len(eight)-Digits:]
		if got := Code(rfcSecret, time.Unix(unix, 0)); got != want {
			t.Errorf("T = %d: Code = %s, want %s", unix, got, want)
		}
	}
}

// Check accepts the code of the current step and of the steps within Skew,
// returns the step that matched, and refuses anything else.
func TestCheck(t *testing.T) {
	now := time.Unix(1111111111, 0)
	step := Step(now)
	for _, offset := range []int64{-1, 0, 1} {
		code := codeAt(rfcSecret, step+offset)
		got, ok := Check(rfcSecret, code, now)
		if !ok || got != step+offset {
			t.Errorf("offset %d: Check = %d, %v, want %d, true", offset, got, ok, step+offset)
		}
	}
	for _, offset := range []int64{-2, 2} {
		if _, ok := Check(rfcSecret, codeAt(rfcSecret, step+offset), now); ok {
			t.Errorf("offset %d: a code two steps away is accepted", offset)
		}
	}
	other := []byte("another secret of twenty")
	if _, ok := Check(other, Code(rfcSecret, now), now); ok {
		t.Error("a code of another secret is accepted")
	}
	for _, code := range []string{"", "12345", "1234567", "12a456", " 05047", "050471 "} {
		if _, ok := Check(rfcSecret, code, now); ok {
			t.Errorf("Check(%q) accepts a code that is not six digits", code)
		}
	}
}

func TestSecretEncoding(t *testing.T) {
	encoded := EncodeSecret(rfcSecret)
	if want := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; encoded != want {
		t.Errorf("EncodeSecret = %s, want %s", encoded, want)
	}
	for _, typed := range []string{encoded, strings.ToLower(encoded), "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ", encoded + "===="} {
		secret, err := DecodeSecret(typed)
		if err != nil || string(secret) != string(rfcSecret) {
			t.Errorf("DecodeSecret(%q) = %q, %v", typed, secret, err)
		}
	}
	if _, err := DecodeSecret("not base32!"); err == nil {
		t.Error("DecodeSecret accepts a string that is not base32")
	}
}

// The link carries the label, the secret, and the fixed parameters, escaped
// so that an issuer with spaces, a colon, or an ampersand reads back as it
// was.
func TestURI(t *testing.T) {
	link := URI("Acme & Co: Admin", "ada@example.com", rfcSecret)
	if strings.Contains(link, "+") {
		t.Errorf("the link has a '+', which some apps show as it is: %s", link)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "otpauth" || parsed.Host != "totp" {
		t.Errorf("link = %s, want otpauth://totp/...", link)
	}
	issuer, account, ok := strings.Cut(strings.TrimPrefix(parsed.EscapedPath(), "/"), ":")
	if !ok {
		t.Fatalf("the label has no separator: %s", parsed.EscapedPath())
	}
	for part, want := range map[string]string{issuer: "Acme & Co: Admin", account: "ada@example.com"} {
		if got, err := url.PathUnescape(part); err != nil || got != want {
			t.Errorf("label part %q reads back as %q, want %q", part, got, want)
		}
	}
	query := parsed.Query()
	for key, want := range map[string]string{
		"secret": EncodeSecret(rfcSecret), "issuer": "Acme & Co: Admin",
		"algorithm": "SHA1", "digits": "6", "period": "30",
	} {
		if got := query.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}
