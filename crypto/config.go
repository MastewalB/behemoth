package crypto

import (
	"context"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/types"
)

// Config is the security configuration an application hands to Boot. Boot
// builds the types.Crypto bundle from it; applications never assemble the
// individual hashers, signers and encryptors themselves.
type Config struct {
	// Secrets supplies the master secret(s) every purpose-specific key is
	// derived from. Required.
	Secrets    types.SecretSource
	KeyManager KeyManagerConfig

	// Password tunes Argon2id password hashing. nil = DefaultParams.
	Password *Params
}

// New builds every cryptographic component from cfg, all sharing one
// KeyManager. ctx bounds the KeyManager's secret watch, if the source
// supports hot rotation, so it should live as long as the application.
func New(ctx context.Context, cfg Config, tel *types.Telemetry) (types.Crypto, error) {
	if cfg.Secrets == nil {
		return types.Crypto{}, behemotherr.NewConfigurationError("crypto.New", "a SecretSource is required", nil)
	}
	if tel == nil {
		tel = types.NewTelemetry(nil, nil, nil)
	}

	km, err := NewDefaultKeyManager(ctx, cfg.KeyManager, cfg.Secrets, tel)
	if err != nil {
		return types.Crypto{}, err
	}
	rnd := NewRandomizer()

	return types.Crypto{
		Keys:       km,
		Random:     rnd,
		Secrets:    NewSecretHasher(km),
		Passwords:  NewArgon2idHasher(cfg.Password, km),
		CookieSign: NewSigner(km, types.KeyPurposeCookieSign),
		JWTSign:    NewSigner(km, types.KeyPurposeJWTSign),
		AtRest:     NewEncryptor(km, rnd),
	}, nil
}
