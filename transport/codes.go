package transport

import (
	"context"
	"fmt"
	"strings"

	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/types"
)

// maxCodeLength bounds CodeOptions.Length. A longer secret is a token's job.
const maxCodeLength = 12

// DefaultCodeManager is the types.CodeManager Boot puts on the AuthContext.
// Codes are rows of verification_codes, written through the store, and are
// hashed with the keyed hasher tokens use (Crypto.Secrets), so a copy of the
// table does not give the codes away.
type DefaultCodeManager struct {
	st     *store.Store
	crypto types.Crypto
}

// NewCodeManager builds the default CodeManager.
func NewCodeManager(st *store.Store, crypto types.Crypto) *DefaultCodeManager {
	return &DefaultCodeManager{st: st, crypto: crypto}
}

// hashed is what is hashed for a code: the kind and the subject with it, so
// that a hash copied to another row matches nothing there.
func hashed(kind types.CodeKind, subject, code string) string {
	return string(kind) + "\x00" + subject + "\x00" + code
}

// Issue implements [types.CodeManager].
func (m *DefaultCodeManager) Issue(ctx context.Context, kind types.CodeKind, subject string, opts types.CodeOptions) (string, *models.VerificationCode, error) {
	const op = "CodeManager.Issue"
	if kind == "" || subject == "" {
		return "", nil, errs.NewConfigurationError(op, "a code needs a kind and a subject", nil)
	}
	if opts.Length == 0 {
		opts.Length = types.DefaultCodeLength
	}
	if opts.TTL == 0 {
		opts.TTL = types.DefaultCodeTTL
	}
	if opts.MaxAttempts == 0 {
		opts.MaxAttempts = types.DefaultCodeMaxAttempts
	}
	if opts.Length < 4 || opts.Length > maxCodeLength || opts.TTL < 0 || opts.MaxAttempts < 1 {
		return "", nil, errs.NewConfigurationError(op,
			fmt.Sprintf("code options are invalid: length %d (4 to %d), TTL %s, attempts %d", opts.Length, maxCodeLength, opts.TTL, opts.MaxAttempts), nil)
	}

	code, err := m.digits(opts.Length)
	if err != nil {
		return "", nil, errs.NewSecurityError(op, "random_generation_failed", err)
	}
	hash, keyVersion, err := m.crypto.Secrets.Hash(hashed(kind, subject, code))
	if err != nil {
		return "", nil, err
	}
	issued := &models.VerificationCode{
		Kind: kind, Subject: subject, CodeHash: hash, KeyVersion: keyVersion,
		AttemptsLeft: opts.MaxAttempts, Metadata: opts.Metadata,
		ExpiresAt: m.st.Now().Add(opts.TTL),
	}
	if err := m.st.ReplaceVerificationCode(ctx, issued); err != nil {
		return "", nil, err
	}
	return code, issued, nil
}

// digits returns n decimal digits, each uniform: a random byte of 250 or
// more is dropped, since 256 is not a multiple of 10.
func (m *DefaultCodeManager) digits(n int) (string, error) {
	var b strings.Builder
	for b.Len() < n {
		raw, err := m.crypto.Random.SecureRandomBytes(2 * n)
		if err != nil {
			return "", err
		}
		for _, r := range raw {
			if r < 250 && b.Len() < n {
				b.WriteByte('0' + r%10)
			}
		}
	}
	return b.String(), nil
}

// Consume implements [types.CodeManager]. The attempt is taken before the
// guess is compared, so that guesses arriving together can't share one.
func (m *DefaultCodeManager) Consume(ctx context.Context, kind types.CodeKind, subject, code string) (*models.VerificationCode, error) {
	const op = "CodeManager.Consume"
	found, err := m.st.SpendVerificationCodeAttempt(ctx, kind, subject)
	if errs.IsNotFound(err) {
		return nil, errs.NewCodeError(op, "no code, or no attempts left")
	}
	if err != nil {
		return nil, err
	}
	if !found.ExpiresAt.After(m.st.Now()) {
		return nil, errs.NewCodeError(op, "the code expired")
	}
	match, err := m.crypto.Secrets.Verify(hashed(kind, subject, code), found.CodeHash, found.KeyVersion)
	if err != nil {
		return nil, err
	}
	if !match {
		return nil, errs.NewCodeError(op, "wrong code")
	}
	// The at-most-once step: of two calls with the right code, one deletes
	// the row and the other finds it gone.
	if err := m.st.DeleteVerificationCode(ctx, found.ID); err != nil {
		if errs.IsNotFound(err) {
			return nil, errs.NewCodeError(op, "the code was used")
		}
		return nil, err
	}
	return found, nil
}

// Revoke implements [types.CodeManager].
func (m *DefaultCodeManager) Revoke(ctx context.Context, kind types.CodeKind, subject string) error {
	return m.st.DeleteVerificationCodeFor(ctx, kind, subject)
}

var _ types.CodeManager = (*DefaultCodeManager)(nil)
