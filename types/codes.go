package types

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
)

// CodeKind is models.CodeKind: what a one-time code is for. A plugin defines
// the kinds it issues, prefixed with its name.
type CodeKind = models.CodeKind

// Defaults of CodeOptions.
const (
	DefaultCodeLength      = 6
	DefaultCodeTTL         = 5 * time.Minute
	DefaultCodeMaxAttempts = 5
)

// CodeOptions says how a code is issued. The zero value is usable.
type CodeOptions struct {
	// Length is the number of digits. Zero means DefaultCodeLength.
	Length int
	// TTL is how long the code works. Zero means DefaultCodeTTL.
	TTL time.Duration
	// MaxAttempts is how many times the code may be tried, the right guess
	// included. Zero means DefaultCodeMaxAttempts.
	MaxAttempts int
	// Metadata is stored with the code and returned when it is consumed:
	// the number a user is adding, for example. Plain values only.
	Metadata behemoth.M
}

// CodeManager issues and checks one-time codes: short numeric secrets a
// person reads from a text message and types back.
//
// It is the counterpart of TokenManager for a secret too short to be found
// by its own hash. A token is a long random string, looked up by its hash. A
// code is looked up by who it is for (kind and subject), allows a few
// attempts and then dies, and there is one live code per kind and subject.
//
// It fires no hook points and records no audit events; the flow that uses a
// code has points of its own.
type CodeManager interface {
	// Issue creates a code for kind and subject and returns it. Only its
	// hash is stored. An earlier code for the same kind and subject stops
	// working.
	Issue(ctx context.Context, kind CodeKind, subject string, opts CodeOptions) (code string, issued *models.VerificationCode, err error)

	// Consume checks code against the live code for kind and subject. A
	// match uses the code up and returns it, with its metadata. Every other
	// outcome is an error for which IsCodeRejection reports true: no code,
	// an expired one, a wrong guess, or no attempts left. A wrong guess
	// costs one attempt, also when several arrive at once.
	Consume(ctx context.Context, kind CodeKind, subject, code string) (*models.VerificationCode, error)

	// Revoke removes the live code for kind and subject, if there is one.
	Revoke(ctx context.Context, kind CodeKind, subject string) error
}
