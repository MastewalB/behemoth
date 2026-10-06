package crypto

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/types"
	"github.com/stretchr/testify/assert"
)

// Helper function to create hex-encoded secrets for testing
func hexSecret(data []byte) string {
	return hex.EncodeToString(data)
}

// Helper to create test secrets
func createTestSecrets(versions ...int) map[int]string {
	secrets := make(map[int]string)
	for _, v := range versions {
		// Create deterministic key material: "key-v{version}" repeated to meet min length
		key := []byte("key-v" + string(rune('0'+v)))
		// Pad to at least minSecretBytes (assuming 32 bytes min)
		for len(key) < 32 {
			key = append(key, key...)
		}
		secrets[v] = hexSecret(key[:32])
	}
	return secrets
}

func TestNewDefaultKeyManager(t *testing.T) {
	tests := []struct {
		name        string
		cfg         KeyManagerConfig
		source      types.SecretSource
		expectError bool
		errContains string
	}{
		{
			name:        "valid initialization",
			cfg:         KeyManagerConfig{},
			source:      NewSecretSource(nil),
			expectError: false,
		},
		{
			name:        "no secrets",
			cfg:         KeyManagerConfig{},
			source:      NewSecretSource(&TestParam{EmptySecret: true}),
			expectError: true,
		},
		{
			name:        "current version not in secrets",
			cfg:         KeyManagerConfig{},
			source:      NewSecretSource(&TestParam{NoCurrent: true}),
			expectError: true,
			errContains: "current version",
		},
		{
			name:        "invalid hex in secret",
			cfg:         KeyManagerConfig{},
			source:      NewSecretSource(&TestParam{InvalidHex: true}),
			expectError: true,
			errContains: "not valid hex",
		},
		// {
		// 	name:        "secret too short",
		// 	cfg:         KeyManagerConfig{},
		// 	source:      NewSecretSource(&TestParam{Bytes: 10}),
		// 	expectError: true,
		// 	errContains: "bytes, need >=",
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			km, err := NewDefaultKeyManager(t.Context(), tt.cfg, tt.source, tel)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, km)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, km)
			}
		})
	}
}

func TestDefaultKeyManager_Current(t *testing.T) {
	cfg := KeyManagerConfig{}

	km, err := NewDefaultKeyManager(t.Context(), cfg, NewSecretSource(&TestParam{Len: 2}), tel)
	assert.NoError(t, err)

	key, version, err := km.Current(types.KeyPurposeTokenHash)
	assert.NoError(t, err)
	assert.Equal(t, 2, version)
	assert.NotEmpty(t, key)

	// Test retrieving version 1 (historical)
	key1, err := km.GetByVersion(types.KeyPurposeCookieSign, 1)
	assert.NoError(t, err)
	assert.NotEmpty(t, key1)

	// Test retrieving version 2 (current)
	key2, err := km.GetByVersion(types.KeyPurposeCookieSign, 2)
	assert.NoError(t, err)
	assert.NotEmpty(t, key2)

	// Test version doesn't exist
	_, err = km.GetByVersion(types.KeyPurposeCookieSign, 99)
	assert.Error(t, err)
}

func TestDefaultKeyManager_SameSecretRegeneratesSameKey(t *testing.T) {
	// First instance
	cfg1 := KeyManagerConfig{}

	km1, err := NewDefaultKeyManager(t.Context(), cfg1, NewSecretSource(&TestParam{Len: 1}), tel)
	assert.NoError(t, err)

	key1, version1, err := km1.Current(types.KeyPurposeTokenHash)
	assert.NoError(t, err)
	assert.Equal(t, 1, version1)

	// Second instance with same secret
	cfg2 := KeyManagerConfig{}

	km2, err := NewDefaultKeyManager(t.Context(), cfg2, NewSecretSource(&TestParam{Len: 1}), tel)
	assert.NoError(t, err)

	key2, version2, err := km2.Current(types.KeyPurposeTokenHash)
	assert.NoError(t, err)
	assert.Equal(t, 1, version2)

	// Keys should be identical
	assert.Equal(t, key1, key2, "Same secret should produce same key")
}

func TestDefaultKeyManager_DifferentSecretProducesDifferentKey(t *testing.T) {
	cfg1 := KeyManagerConfig{}

	km1, err := NewDefaultKeyManager(t.Context(), cfg1, NewSecretSource(&TestParam{Len: 1}), tel)
	assert.NoError(t, err)

	key1, _, err := km1.Current(types.KeyPurposeTokenHash)
	assert.NoError(t, err)

	cfg2 := KeyManagerConfig{}

	km2, err := NewDefaultKeyManager(t.Context(), cfg2, NewSecretSource(&TestParam{Len: 2}), tel)
	assert.NoError(t, err)

	key2, _, err := km2.Current(types.KeyPurposeTokenHash)
	assert.NoError(t, err)

	// Keys should be different
	assert.NotEqual(t, key1, key2, "Different secrets should produce different keys")
}

// func TestDefaultKeyManager_Caching(t *testing.T) {
// 	cfg := KeyManagerConfig{
// 		Secrets: map[int]string{
// 			1: hex32("cached-secret"),
// 		},
// 		CurrentVersion: 1,
// 	}

// 	km, err := NewDefaultKeyManager(cfg)
// 	require.NoError(t, err)

// 	// First call - should compute
// 	key1, version1, err := km.Current(KeyPurposeTokenHash)
// 	require.NoError(t, err)

// 	// Second call - should return cached
// 	key2, version2, err := km.Current(KeyPurposeTokenHash)
// 	require.NoError(t, err)

// 	// Should be identical and cached
// 	assert.Equal(t, key1, key2)
// 	assert.Equal(t, version1, version2)
// }

func TestDefaultKeyManager_ConcurrentAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrent test in short mode")
	}

	cfg := KeyManagerConfig{}

	km, err := NewDefaultKeyManager(t.Context(), cfg, NewSecretSource(nil), tel)
	assert.NoError(t, err)

	const goroutines = 50
	errChan := make(chan error, goroutines*2)

	for range goroutines {
		// Concurrent Current calls
		go func() {
			_, _, err := km.Current(types.KeyPurposeTokenHash)
			errChan <- err
		}()

		// Concurrent GetByVersion calls
		go func() {
			_, err := km.GetByVersion(types.KeyPurposeTokenHash, 1)
			errChan <- err
		}()
	}

	// Collect results
	for range goroutines * 2 {
		err := <-errChan
		assert.NoError(t, err)
	}
}

// Benchmark tests
func BenchmarkDefaultKeyManager_Current(b *testing.B) {

	cfg := KeyManagerConfig{}

	for b.Loop() {
		km, err := NewDefaultKeyManager(b.Context(), cfg, NewSecretSource(nil), tel)
		if err != nil {
			b.Fatal(err)
		}

		_, _, err = km.Current(types.KeyPurposeTokenHash)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDefaultKeyManager_GetByVersion(b *testing.B) {

	cfg := KeyManagerConfig{}

	for b.Loop() {
		km, err := NewDefaultKeyManager(b.Context(), cfg, NewSecretSource(nil), tel)
		if err != nil {
			b.Fatal(err)
		}

		_, err = km.GetByVersion(types.KeyPurposeTokenHash, 1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

type MockSecretSource struct {
	secrets map[int]string
	current int
}

type TestParam struct {
	Bytes       int
	Len         int
	EmptySecret bool
	NoCurrent   bool
	InvalidHex  bool
}

func NewSecretSource(param *TestParam) *MockSecretSource {
	ss := &MockSecretSource{}
	ss.secrets = make(map[int]string)

	targetVersion := 11
	insertInvalidTarget := false
	invalidHex := false

	if param != nil {
		if param.Len > 0 {
			targetVersion = param.Len
		}

		if param.EmptySecret {
			return ss
		} else if param.NoCurrent {
			insertInvalidTarget = true
		} else if param.InvalidHex {
			invalidHex = true
		}
	}

	// valid path

	for i := range targetVersion + 1 {
		if invalidHex {
			ss.secrets[i] = fmt.Sprintf("secretsecretsecretsecretsecretsecret-%d", i)
		} else {
			ss.secrets[i] = hexSecret(fmt.Appendf(nil, "secretsecretsecretsecretsecretsecret-%d", i))
		}
	}
	ss.current = targetVersion

	if insertInvalidTarget {
		// add one to targetVersion so that it's not in the secrets
		ss.current = targetVersion + 1
	}
	return ss
}

func (m *MockSecretSource) Load(ctx context.Context) (map[int]string, int, error) {
	return m.secrets, m.current, nil
}

var tel = telemetry.New(nil, nil, nil)
