package crypto_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"math/bits"
	"regexp"
	"testing"

	"github.com/MastewalB/behemoth/crypto"
	"github.com/MastewalB/behemoth/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SecureRandomBytes returns as many bytes as asked for. SecureRandomString
// returns that many bytes as unpadded base64url, so its length is the
// encoded length and not n.
func TestRandomizerLengths(t *testing.T) {
	r := crypto.NewRandomizer()
	base64url := regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
	for _, n := range []int{1, 2, 3, 12, 16, 32, 1000} {
		b, err := r.SecureRandomBytes(n)
		require.NoError(t, err)
		assert.Len(t, b, n)

		s, err := r.SecureRandomString(n)
		require.NoError(t, err)
		assert.Len(t, s, base64.RawURLEncoding.EncodedLen(n), "n=%d", n)
		assert.Regexp(t, base64url, s, "no padding, nothing a URL or a cookie would escape")
		decoded, err := base64.RawURLEncoding.DecodeString(s)
		require.NoError(t, err)
		assert.Len(t, decoded, n)
	}
	s, err := r.SecureRandomString(32)
	require.NoError(t, err)
	assert.Len(t, s, 43, "a session token: 32 bytes are 43 characters")
}

// A length that is not positive is an error, not a panic and not an empty
// secret.
func TestRandomizerRefusesALengthThatIsNotPositive(t *testing.T) {
	r := crypto.NewRandomizer()
	for _, n := range []int{0, -1} {
		b, err := r.SecureRandomBytes(n)
		assert.True(t, errs.IsCategory(err, errs.CategoryInternal), "n=%d: %v", n, err)
		assert.Nil(t, b)
		s, err := r.SecureRandomString(n)
		assert.Error(t, err, "n=%d", n)
		assert.Empty(t, s)
	}
}

// The output is not constant or repeated. This catches a broken source,
// such as one that returns zeros or the same bytes; it is not a test of
// crypto/rand, which the randomizer reads.
func TestRandomizerOutputVaries(t *testing.T) {
	r := crypto.NewRandomizer()
	seen := make(map[string]bool, 1000)
	for range 1000 {
		s, err := r.SecureRandomString(16)
		require.NoError(t, err)
		require.False(t, seen[s], "a 16-byte value came twice")
		seen[s] = true
	}

	// About half of the bits of 1 MiB are set: the deviation allowed is
	// over 50 standard deviations, so a working source never fails it.
	b, err := r.SecureRandomBytes(1 << 20)
	require.NoError(t, err)
	ones := 0
	for _, x := range b {
		ones += bits.OnesCount8(x)
	}
	assert.InDelta(t, 0.5, float64(ones)/float64(8*len(b)), 0.01)
	assert.False(t, bytes.Equal(b[:32], make([]byte, 32)))
}

// A failed or short read of crypto/rand is a security error, and no bytes
// are returned.
func TestRandomizerReadFailure(t *testing.T) {
	saved := rand.Reader
	t.Cleanup(func() { rand.Reader = saved })
	r := crypto.NewRandomizer()

	rand.Reader = failingReader{}
	b, err := r.SecureRandomBytes(32)
	securityError(t, err, "crypto_read_failure")
	assert.Nil(t, b)

	rand.Reader = bytes.NewReader(make([]byte, 8))
	b, err = r.SecureRandomBytes(32)
	securityError(t, err, "crypto_read_failure", "8 bytes when 32 were asked for")
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	assert.Nil(t, b)

	rand.Reader = failingReader{}
	s, err := r.SecureRandomString(32)
	securityError(t, err, "crypto_read_failure")
	assert.Empty(t, s)
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy source unavailable") }
