package errs

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A duplicate key error names the columns of the key it broke. The store's
// conflict for a column declared unique keeps it in the chain, so the write
// is still a duplicate key, and its columns can still be read, through a
// wrapping or a join too.
func TestDuplicateKeyColumns(t *testing.T) {
	cause := errors.New("UNIQUE constraint failed: users.email")
	duplicate := NewDuplicateKeyOn("Create", "users", []string{"email"}, cause)
	assert.True(t, IsDuplicateKey(duplicate))
	assert.Equal(t, []string{"email"}, DuplicateKeyColumns(duplicate))
	assert.Equal(t, "users_already_exists", ClassifyCode(duplicate), "the code a client got before is kept")
	assert.ErrorIs(t, duplicate, cause)

	taken := NewTaken("Store.Create", "users", "phone_number", "phone_number_taken", duplicate)
	assert.True(t, IsCategory(taken, CategoryConflict), "a conflict, which refuses the request")
	assert.True(t, IsRejection(taken))
	assert.Equal(t, "phone_number_taken", taken.Code)
	assert.Equal(t, "phone number is already taken", taken.PublicMessage)
	assert.True(t, IsDuplicateKey(taken), "the duplicate key is in the chain")
	assert.Equal(t, []string{"email"}, DuplicateKeyColumns(taken))

	for name, wrapped := range map[string]error{
		"wrapped": fmt.Errorf("sign-up: %w", taken),
		"joined":  errors.Join(errors.New("rollback failed"), taken),
	} {
		assert.True(t, IsDuplicateKey(wrapped), name)
		assert.Equal(t, []string{"email"}, DuplicateKeyColumns(wrapped), name)
	}

	unnamed := NewDuplicateKey("Create", "users", cause)
	assert.True(t, IsDuplicateKey(unnamed))
	assert.Nil(t, DuplicateKeyColumns(unnamed), "an adapter that could not tell names nothing")
	for name, other := range map[string]error{
		"another category": NewDatabaseError("Create", cause),
		"untyped":          cause,
		"nil":              nil,
	} {
		assert.False(t, IsDuplicateKey(other), name)
		assert.Nil(t, DuplicateKeyColumns(other), name)
	}
}
