package crypto

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"sync"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/types"
	"golang.org/x/crypto/hkdf"
)

type KeyManagerConfig struct {
	MinSecretBytes int
	Environment    types.Environment
}

func (c KeyManagerConfig) withDefaults() KeyManagerConfig {
	if c.MinSecretBytes == 0 {
		c.MinSecretBytes = 32
	}

	return c
}

const devDefaultSecret = "dev-insecure-default-secret-do-not-use-in-production"

type derivedKeyCacheKey struct {
	version int
	purpose types.KeyPurpose
}

type DefaultKeyManager struct {
	mu      sync.RWMutex
	secrets map[int][]byte
	current int
	cache   map[derivedKeyCacheKey][]byte
	cfg     KeyManagerConfig
	tel     *telemetry.Telemetry
}

func NewDefaultKeyManager(ctx context.Context, cfg KeyManagerConfig, source types.SecretSource, tel *telemetry.Telemetry) (*DefaultKeyManager, error) {
	tel = telemetry.OrDefault(tel).Named("crypto")
	raw, current, err := source.Load(ctx)
	if err != nil {
		return nil, behemotherr.NewConfigurationError("KeyManager.Load", "initial secret load failed", err)
	}

	decoded, err := decodeAndValidate(raw, current, cfg)
	if err != nil {
		return nil, err
	}

	km, err := buildKeyManager(decoded, current, cfg, tel)
	if err != nil {
		return nil, err
	}

	if watchable, ok := source.(types.WatchableSecretSource); ok {
		if err := watchable.Watch(ctx, km.applyUpdate); err != nil {
			tel.Logger.Warn(ctx, "failed to start secret watch; rotation will require a restart", telemetry.ErrorFields(err))
		} else {
			tel.Logger.Info(ctx, "secret hot-rotation enabled", nil)
		}
	} else {
		tel.Logger.Info(ctx, "secret source does not support hot rotation; rotation requires a restart", nil)
	}

	return km, nil
}

func (km *DefaultKeyManager) Current(purpose types.KeyPurpose) (key []byte, version int, err error) {
	key, err = km.deriveKey(purpose, km.current)
	return key, km.current, err
}

func (km *DefaultKeyManager) GetByVersion(purpose types.KeyPurpose, version int) (key []byte, err error) {
	return km.deriveKey(purpose, version)
}

func (km *DefaultKeyManager) CurrentVersion() int {
	return km.current
}

func decodeAndValidate(raw map[int]string, current int, cfg KeyManagerConfig) (map[int][]byte, error) {
	cfg = cfg.withDefaults()

	if len(raw) == 0 {
		return nil, behemotherr.NewConfigurationError("KeyManager.Load", "source returned no secrets", nil)
	}

	if _, ok := raw[current]; !ok {
		return nil, behemotherr.NewConfigurationError("KeyManager.Load",
			fmt.Sprintf("current version %d not present among provided secrets", current), nil)
	}

	decoded := make(map[int][]byte, len(raw))
	for version, value := range raw {
		if cfg.Environment == types.EnvProduction && (value == "" || value == devDefaultSecret) {
			return nil, behemotherr.NewConfigurationError("KeyManager.Load",
				fmt.Sprintf("refusing empty/default secret for version %d in production", version), nil)
		}
		b, err := hex.DecodeString(value)
		if err != nil {
			return nil, behemotherr.NewConfigurationError("KeyManager.Load",
				fmt.Sprintf("version %d is not valid hex", version), err)
		}
		if len(b) < cfg.MinSecretBytes {
			return nil, behemotherr.NewConfigurationError("KeyManager.Load",
				fmt.Sprintf("version %d is %d bytes, need >= %d", version, len(b), cfg.MinSecretBytes), nil)
		}
		decoded[version] = b
	}

	return decoded, nil
}

func (km *DefaultKeyManager) deriveKey(purpose types.KeyPurpose, version int) ([]byte, error) {
	ck := derivedKeyCacheKey{version: version, purpose: purpose}

	km.mu.RLock()
	if derived, ok := km.cache[ck]; ok {
		km.mu.RUnlock()
		return derived, nil
	}
	km.mu.RUnlock()

	km.mu.Lock()
	defer km.mu.Unlock()

	// Check again in case it was added while we were waiting for the lock
	if derived, ok := km.cache[ck]; ok {
		return derived, nil
	}

	masterSecret, ok := km.secrets[version]
	if !ok {
		return nil, behemotherr.NewSecurityError("KeyManager.Derive", "unknown_key_version",
			fmt.Errorf("no key material for version %d, purpose %q", version, purpose))
	}

	hk := hkdf.New(sha256.New, masterSecret, nil, []byte(purpose))
	derived := make([]byte, 32)
	if _, err := hk.Read(derived); err != nil {
		return nil, behemotherr.NewSecurityError("KeyManager.Derive", "hkdf_failure", err)
	}

	km.cache[ck] = derived
	return derived, nil
}

// applyUpdate is the hot-reload callback. It's triggered either by a watch callback or manually via an admin API.
// It only adds the new keys in secret. It doesn't remove the "old" keys. Removal must be done via the RemoveVersion function.
// It validates the incoming update before applying to the running KeyManager.
// The secret souce must be responsible for making sure that the new versions do not clash with the old ones.
func (km *DefaultKeyManager) applyUpdate(rawSecrets map[int]string, newCurrent int) {
	decoded, err := decodeAndValidate(rawSecrets, newCurrent, km.cfg)
	if err != nil {
		km.tel.Logger.Error(context.Background(), "rejected invalid secret rotation update", telemetry.ErrorFields(err))
		return // old state keeps serving untouched
	}
	km.mu.Lock()
	defer km.mu.Unlock()

	// write the new secrets.
	// if the new version overwrites an older one, all keys created with the old secret will be invalid
	maps.Copy(km.secrets, decoded)

	km.current = newCurrent
	km.tel.Logger.Info(context.Background(), "secret rotation applied", behemoth.M{"newCurrent": newCurrent})
	km.tel.RecordAudit(context.Background(), telemetry.AuditEvent{
		Type: telemetry.AuditSecretRotated, ActorType: telemetry.ActorSystem,
		Metadata: behemoth.M{"current_version": newCurrent},
	})

}

// RemoveVersion is explicit secret removal method
// It's impossible to remove the current secret before adding a new one
func (km *DefaultKeyManager) RemoveVersion(version int) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if version == km.current {
		return behemotherr.NewValidationError("KeyManager.RemoveVersion", "version",
			fmt.Errorf("cannot remove the current key version (%d)", version))
	}

	if _, ok := km.secrets[version]; !ok {
		return behemotherr.NewNotFound("KeyManager.RemoveVersion", "key_version", nil)
	}

	// remove it from the secret map
	delete(km.secrets, version)

	// delete all keys created with the secret
	for k := range km.cache {
		if k.version == version {
			delete(km.cache, k)
		}
	}

	return nil
}

func buildKeyManager(secrets map[int][]byte, current int, cfg KeyManagerConfig, tel *telemetry.Telemetry) (*DefaultKeyManager, error) {
	if _, ok := secrets[current]; !ok {
		return nil, behemotherr.NewConfigurationError("KeyManager.Build",
			fmt.Sprintf("current version %d missing after decode", current), nil) // defensive; decodeAndValidate already guarantees this
	}

	return &DefaultKeyManager{
		secrets: secrets,
		current: current,
		cache:   make(map[derivedKeyCacheKey][]byte),
		cfg:     cfg,
		tel:     tel,
	}, nil
}
