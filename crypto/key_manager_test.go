package crypto

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"testing"

	"github.com/go-behemoth/behemoth/telemetry"
	"github.com/go-behemoth/behemoth/telemetry/telemetrytest"
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
		source      SecretSource
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

	key, version, err := km.Current(KeyPurposeTokenHash)
	assert.NoError(t, err)
	assert.Equal(t, 2, version)
	assert.NotEmpty(t, key)

	// Test retrieving version 1 (historical)
	key1, err := km.GetByVersion(KeyPurposeCookieSign, 1)
	assert.NoError(t, err)
	assert.NotEmpty(t, key1)

	// Test retrieving version 2 (current)
	key2, err := km.GetByVersion(KeyPurposeCookieSign, 2)
	assert.NoError(t, err)
	assert.NotEmpty(t, key2)

	// Test version doesn't exist
	_, err = km.GetByVersion(KeyPurposeCookieSign, 99)
	assert.Error(t, err)
}

func TestDefaultKeyManager_SameSecretRegeneratesSameKey(t *testing.T) {
	// First instance
	cfg1 := KeyManagerConfig{}

	km1, err := NewDefaultKeyManager(t.Context(), cfg1, NewSecretSource(&TestParam{Len: 1}), tel)
	assert.NoError(t, err)

	key1, version1, err := km1.Current(KeyPurposeTokenHash)
	assert.NoError(t, err)
	assert.Equal(t, 1, version1)

	// Second instance with same secret
	cfg2 := KeyManagerConfig{}

	km2, err := NewDefaultKeyManager(t.Context(), cfg2, NewSecretSource(&TestParam{Len: 1}), tel)
	assert.NoError(t, err)

	key2, version2, err := km2.Current(KeyPurposeTokenHash)
	assert.NoError(t, err)
	assert.Equal(t, 1, version2)

	// Keys should be identical
	assert.Equal(t, key1, key2, "Same secret should produce same key")
}

func TestDefaultKeyManager_DifferentSecretProducesDifferentKey(t *testing.T) {
	cfg1 := KeyManagerConfig{}

	km1, err := NewDefaultKeyManager(t.Context(), cfg1, NewSecretSource(&TestParam{Len: 1}), tel)
	assert.NoError(t, err)

	key1, _, err := km1.Current(KeyPurposeTokenHash)
	assert.NoError(t, err)

	cfg2 := KeyManagerConfig{}

	km2, err := NewDefaultKeyManager(t.Context(), cfg2, NewSecretSource(&TestParam{Len: 2}), tel)
	assert.NoError(t, err)

	key2, _, err := km2.Current(KeyPurposeTokenHash)
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
			_, _, err := km.Current(KeyPurposeTokenHash)
			errChan <- err
		}()

		// Concurrent GetByVersion calls
		go func() {
			_, err := km.GetByVersion(KeyPurposeTokenHash, 1)
			errChan <- err
		}()
	}

	// Collect results
	for range goroutines * 2 {
		err := <-errChan
		assert.NoError(t, err)
	}
}

// While rotations run, every key Current returns is the key of the version
// it returns with it. Current reads the current version once, under the
// lock; reading it twice could pair one version's key with the other's
// number, and a signature would name a key that did not make it. Run with
// -race, the test also catches an unlocked read.
func TestDefaultKeyManager_CurrentDuringRotation(t *testing.T) {
	secrets := createTestSecrets(1, 2)
	km, err := NewDefaultKeyManager(t.Context(), KeyManagerConfig{}, StaticSecretSource{Secrets: secrets, Current: 1}, tel)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
				km.applyUpdate(secrets, 1+i%2)
			}
		}
	}()
	for range 20000 {
		key, version, err := km.Current(KeyPurposeTokenHash)
		if err != nil {
			t.Fatal(err)
		}
		want, err := km.GetByVersion(KeyPurposeTokenHash, version)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(key, want) {
			t.Fatalf("Current returned version %d with another version's key", version)
		}
	}
	close(done)
	<-stopped
}

// An update that changes nothing, such as a poll that found the same
// secrets, is not a rotation: it is neither logged nor audited. A new
// current version and a new secret are.
func TestDefaultKeyManager_UpdateThatChangesNothing(t *testing.T) {
	tel, rec := telemetrytest.New()
	secrets := createTestSecrets(1, 2)
	km, err := NewDefaultKeyManager(t.Context(), KeyManagerConfig{}, StaticSecretSource{Secrets: secrets, Current: 2}, tel)
	if err != nil {
		t.Fatal(err)
	}
	rotations := func() int { return len(rec.Audit.OfType(telemetry.AuditSecretRotated)) }

	km.applyUpdate(secrets, 2)
	km.applyUpdate(map[int]string{2: secrets[2]}, 2)
	assert.Zero(t, rotations(), "the same secrets, or fewer of them")

	km.applyUpdate(secrets, 1)
	assert.Equal(t, 1, rotations(), "another current version")
	assert.Equal(t, 1, km.CurrentVersion())

	km.applyUpdate(createTestSecrets(1, 2, 3), 1)
	assert.Equal(t, 2, rotations(), "a new secret")
	assert.Equal(t, []int{1, 2, 3}, km.Versions())

	applied := 0
	for _, line := range rec.Logger.Entries() {
		if line.Message == "secret rotation applied" {
			applied++
		}
	}
	assert.Equal(t, 2, applied)
}

// An update that gives a version the key manager holds another secret is
// refused whole and logged at Error, even when it also adds a version or
// moves the current one: the manager keeps its secrets and the keys derived
// from them. A version names one secret for good.
func TestDefaultKeyManager_RefusesANewSecretForAHeldVersion(t *testing.T) {
	tel, rec := telemetrytest.New()
	secrets := createTestSecrets(1, 2)
	km, err := NewDefaultKeyManager(t.Context(), KeyManagerConfig{}, StaticSecretSource{Secrets: secrets, Current: 2}, tel)
	if err != nil {
		t.Fatal(err)
	}
	before, err := km.GetByVersion(KeyPurposeTokenHash, 2)
	if err != nil {
		t.Fatal(err)
	}
	other := createTestSecrets(7)[7]

	for name, update := range map[string]struct {
		secrets map[int]string
		current int
	}{
		"version 2 changed":                        {map[int]string{1: secrets[1], 2: other}, 2},
		"version 2 changed, version 3 added":       {map[int]string{1: secrets[1], 2: other, 3: createTestSecrets(3)[3]}, 3},
		"version 1 changed, the current moved":     {map[int]string{1: other, 2: secrets[2]}, 1},
		"version 2 changed, only it in the update": {map[int]string{2: other}, 2},
	} {
		rec.Logger.Reset()
		km.applyUpdate(update.secrets, update.current)

		assert.Equal(t, 2, km.CurrentVersion(), name)
		assert.Equal(t, []int{1, 2}, km.Versions(), name)
		key, err := km.GetByVersion(KeyPurposeTokenHash, 2)
		assert.NoError(t, err, name)
		assert.Equal(t, before, key, "%s: the derived key is the held secret's", name)

		lines := rec.Logger.At(slog.LevelError)
		if assert.Len(t, lines, 1, name) {
			assert.Equal(t, "rejected invalid secret rotation update", lines[0].Message)
			assert.Contains(t, fmt.Sprint(lines[0].Fields), "never changes", name)
			assert.NotContains(t, fmt.Sprint(lines[0].Fields), other, "%s: the line does not carry the secret", name)
		}
	}
	assert.Empty(t, rec.Audit.OfType(telemetry.AuditSecretRotated), "no rotation took effect")

	km.applyUpdate(createTestSecrets(1, 2, 3), 3)
	assert.Equal(t, 3, km.CurrentVersion(), "an update that only adds a version is applied")
}

// Benchmark tests
func BenchmarkDefaultKeyManager_Current(b *testing.B) {

	cfg := KeyManagerConfig{}

	for b.Loop() {
		km, err := NewDefaultKeyManager(b.Context(), cfg, NewSecretSource(nil), tel)
		if err != nil {
			b.Fatal(err)
		}

		_, _, err = km.Current(KeyPurposeTokenHash)
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

		_, err = km.GetByVersion(KeyPurposeTokenHash, 1)
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
