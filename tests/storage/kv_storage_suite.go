package models

import (
	"context"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/stretchr/testify/assert"
)

// KeyValueStorageTestSuite is a test suite for KeyValueStorage implementations
type KeyValueStorageTestSuite struct {
	storage behemoth.KeyValueStorage
}

func NewKeyValueStorageTestSuite(storage behemoth.KeyValueStorage) *KeyValueStorageTestSuite {
	return &KeyValueStorageTestSuite{
		storage: storage,
	}
}

func (s *KeyValueStorageTestSuite) RunAllTests(t *testing.T) {
	t.Run("SetAndGet", s.TestSetAndGet)
	t.Run("GetNonExistent", s.TestGetNonExistent)
	t.Run("Delete", s.TestDelete)
	t.Run("DeleteNonExistentKey", s.TestDeleteNonExistent)
	t.Run("Overwrite", s.TestOverwrite)
	t.Run("TTL", s.TestTTL)
	t.Run("EmptyKey", s.TestEmptyKey)
	t.Run("EmptyValue", s.TestEmptyValue)
	t.Run("SpecialCharacters", s.TestSpecialCharacters)
	t.Run("ConcurrentOperations", s.TestConcurrentOperations)
	t.Run("ContextCancellation", s.TestContextCancellation)
	t.Run("ZeroTTL", s.TestZeroTTL)
	t.Run("NegativeTTL", s.TestNegativeTTL)

}

func (s *KeyValueStorageTestSuite) TestSetAndGet(t *testing.T) {
	ctx := context.Background()
	key := "test-key"
	value := "test-value"
	ttl := 3600 // 1 hour

	err := s.storage.Set(ctx, key, value, ttl)
	assert.NoError(t, err)

	got, err := s.storage.Get(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, value, got)
}

func (s *KeyValueStorageTestSuite) TestGetNonExistent(t *testing.T) {
	ctx := context.Background()
	key := "non-existent-key"

	got, err := s.storage.Get(ctx, key)

	assert.Error(t, err)
	assert.Empty(t, got)
}

// TestDelete tests delete operation
func (s *KeyValueStorageTestSuite) TestDelete(t *testing.T) {
	ctx := context.Background()
	key := "delete-test-key"
	value := "to-be-deleted"
	ttl := 3600

	// Set the value
	err := s.storage.Set(ctx, key, value, ttl)
	assert.NoError(t, err)

	// Verify it exists
	got, err := s.storage.Get(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, value, got)

	// Delete it
	err = s.storage.Delete(ctx, key)
	assert.NoError(t, err)

	// Verify
	got, err = s.storage.Get(ctx, key)

	assert.Error(t, err)
	assert.Empty(t, got)
}

func (s *KeyValueStorageTestSuite) TestDeleteNonExistent(t *testing.T) {
	ctx := context.Background()
	key := "delete-test-key"

	err := s.storage.Delete(ctx, key)
	assert.NoError(t, err)
}

func (s *KeyValueStorageTestSuite) TestOverwrite(t *testing.T) {
	ctx := context.Background()
	key := "overwrite-test"
	value1 := "first-value"
	value2 := "second-value"
	ttl := 3600

	// Set first value
	err := s.storage.Set(ctx, key, value1, ttl)
	assert.NoError(t, err)

	// Overwrite with second value
	err = s.storage.Set(ctx, key, value2, ttl)
	assert.NoError(t, err)

	// Verify second value
	got, err := s.storage.Get(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, value2, got)
}

func (s *KeyValueStorageTestSuite) TestTTL(t *testing.T) {
	ctx := context.Background()
	key := "ttl-test-key"
	value := "expiring-value"
	ttl := 1 // 1 second

	err := s.storage.Set(ctx, key, value, ttl)
	assert.NoError(t, err)

	// Verify it exists immediately
	got, err := s.storage.Get(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, value, got)

	// Wait for expiration
	time.Sleep(2 * time.Second)

	// Verify it's expired
	got, err = s.storage.Get(ctx, key)
	assert.Error(t, err)
	assert.Empty(t, got)

}

func (s *KeyValueStorageTestSuite) TestEmptyKey(t *testing.T) {
	ctx := context.Background()
	key := ""
	value := "some-value"
	ttl := 3600

	err := s.storage.Set(ctx, key, value, ttl)
	// Should return error for empty key
	assert.Error(t, err)

	_, err = s.storage.Get(ctx, key)
	assert.Error(t, err)

	err = s.storage.Delete(ctx, key)
	assert.Error(t, err)
}

func (s *KeyValueStorageTestSuite) TestEmptyValue(t *testing.T) {
	ctx := context.Background()
	key := "empty-value-key"
	value := ""
	ttl := 3600

	err := s.storage.Set(ctx, key, value, ttl)
	assert.NoError(t, err)

	got, err := s.storage.Get(ctx, key)
	assert.NoError(t, err)
	assert.Empty(t, got)
}

func (s *KeyValueStorageTestSuite) TestSpecialCharacters(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name  string
		key   string
		value string
	}{
		{"Unicode", "unicode-key", "Hello 世界"},
		{"Spaces", "key with spaces", "value with spaces"},
		{"Special chars", "key!@#$%", "value!@#$%"},
		{"Newlines", "key\nwith\nnewlines", "value\nwith\nnewlines"},
		{"Quotes", `"quoted" key`, `"quoted" value`},
		{"Backslashes", "key\\with\\backslashes", "value\\with\\backslashes"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.storage.Set(ctx, tc.key, tc.value, 3600)
			assert.NoError(t, err)

			got, err := s.storage.Get(ctx, tc.key)
			assert.NoError(t, err)
			assert.Equal(t, tc.value, got)
		})
	}
}

func (s *KeyValueStorageTestSuite) TestConcurrentOperations(t *testing.T) {
	ctx := context.Background()

	const numGoroutines = 100
	const numOperations = 100

	done := make(chan bool)

	// Concurrent writes
	for i := range numGoroutines {
		go func(id int) {
			for range numOperations {
				key := "concurrent-key"
				value := string(rune(id))
				s.storage.Set(ctx, key, value, 3600)
			}
			done <- true
		}(i)
	}

	// Concurrent reads
	for range numGoroutines {
		go func() {
			for range numOperations {
				key := "concurrent-key"
				s.storage.Get(ctx, key)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for range numGoroutines * 2 {
		<-done
	}
}

func (s *KeyValueStorageTestSuite) TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	key := "cancel-test"
	value := "test-value"
	ttl := 3600

	cancel() // Cancel immediately

	err := s.storage.Set(ctx, key, value, ttl)
	assert.Error(t, err)

	_, err = s.storage.Get(ctx, key)
	assert.Error(t, err)

	err = s.storage.Delete(ctx, key)
	assert.Error(t, err)
}

func (s *KeyValueStorageTestSuite) TestZeroTTL(t *testing.T) {
	ctx := context.Background()
	key := "zero-ttl-key"
	value := "test-value"
	ttl := 0

	err := s.storage.Set(ctx, key, value, ttl)
	assert.NoError(t, err)

	// Should still be retrievable
	got, err := s.storage.Get(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, value, got)
}

func (s *KeyValueStorageTestSuite) TestNegativeTTL(t *testing.T) {
	ctx := context.Background()
	key := "negative-ttl-key"
	value := "test-value"
	ttl := -10

	err := s.storage.Set(ctx, key, value, ttl)
	assert.NoError(t, err)

	got, err := s.storage.Get(ctx, key)
	assert.NotNil(t, got)
	assert.NoError(t, err)

}
