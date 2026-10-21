// Package totp computes and checks time-based one-time passwords (RFC 6238)
// the way authenticator apps compute them: an HMAC-SHA-1 of the number of
// 30-second steps since the Unix epoch, truncated to six digits (RFC 4226).
//
// It keeps no state. The caller stores the secret, and, to accept each code
// once, the last step that passed: Check returns the step a code matched,
// and a code whose step is not later than the stored one is a replay.
//
// The parameters are fixed: SHA-1, six digits, and 30 seconds are what every
// authenticator app supports, and some apps ignore other values in the link.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// Digits is the length of a code.
	Digits = 6
	// Period is the length of a time step: how long a code is current.
	Period = 30 * time.Second
	// Skew is how many steps before and after the current one Check
	// accepts, for a clock that is off by up to a period and for the time
	// the user takes to type. RFC 6238 recommends at most one.
	Skew = 1
	// SecretSize is the length of a new secret in bytes: 160 bits, as RFC
	// 4226 recommends. Generate it with a cryptographically secure source.
	SecretSize = 20
)

// modulus is 10^Digits: a code is the truncated HMAC modulo it.
const modulus = 1_000_000

// encoding is how a secret is written for an authenticator app: base32
// (RFC 4648) without padding.
var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Step returns the time step t falls in: the number of whole periods since
// the Unix epoch.
func Step(t time.Time) int64 {
	return t.Unix() / int64(Period/time.Second)
}

// Code returns the code of secret for the time step t falls in.
func Code(secret []byte, t time.Time) string {
	return codeAt(secret, Step(t))
}

// codeAt is the HOTP value of RFC 4226 with step as the counter: the HMAC of
// the counter, truncated at the offset its last byte names, modulo 10^Digits.
func codeAt(secret []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", Digits, value%modulus)
}

// Check reports whether code is the code of secret for the time step of t,
// or for a step within Skew of it, and returns the step it matched. Every
// step is compared, in constant time, so the time taken does not tell which
// one matched. A code that is not Digits digits matches nothing.
func Check(secret []byte, code string, t time.Time) (step int64, ok bool) {
	if len(code) != Digits || strings.Trim(code, "0123456789") != "" {
		return 0, false
	}
	now := Step(t)
	for s := now - Skew; s <= now+Skew; s++ {
		if subtle.ConstantTimeCompare([]byte(codeAt(secret, s)), []byte(code)) == 1 {
			step, ok = s, true // the latest step that matches
		}
	}
	return step, ok
}

// EncodeSecret returns secret the way an authenticator app reads it: base32
// without padding, as in the link URI returns.
func EncodeSecret(secret []byte) string {
	return encoding.EncodeToString(secret)
}

// DecodeSecret reads a secret written by EncodeSecret, or typed from one: in
// either case, with or without padding, and with the spaces apps put in the
// key they show.
func DecodeSecret(s string) ([]byte, error) {
	s = strings.TrimRight(strings.ToUpper(strings.ReplaceAll(s, " ", "")), "=")
	secret, err := encoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("totp: the secret is not base32: %w", err)
	}
	return secret, nil
}

// URI returns the otpauth link that sets an authenticator app up with
// secret: the "Key Uri Format" apps read from a QR code. The label is the
// issuer and the account, such as "Example:ada@example.com", and the
// parameters name the issuer and the fixed algorithm, digits, and period. A
// colon in the issuer or the account is escaped, since a colon separates the
// two in the label.
func URI(issuer, account string, secret []byte) string {
	label := labelPart(issuer) + ":" + labelPart(account)
	query := []string{
		"secret=" + queryPart(EncodeSecret(secret)),
		"issuer=" + queryPart(issuer),
		"algorithm=SHA1",
		fmt.Sprintf("digits=%d", Digits),
		fmt.Sprintf("period=%d", int(Period/time.Second)),
	}
	return "otpauth://totp/" + label + "?" + strings.Join(query, "&")
}

// labelPart escapes a part of the label for the URI's path, with spaces as
// %20 and colons escaped.
func labelPart(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), ":", "%3A")
}

// queryPart escapes a parameter value, with spaces as %20: some apps show a
// "+" as it is.
func queryPart(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}
