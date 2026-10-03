package types

import "github.com/MastewalB/behemoth/types/cryptotypes"

// The cryptography contracts live in package cryptotypes, below types, so
// packages types imports (store) can use them too. These aliases are the
// same types under the names the rest of behemoth and plugins use.
type (
	Crypto     = cryptotypes.Crypto
	KeyPurpose = cryptotypes.KeyPurpose
	KeyManager = cryptotypes.KeyManager

	PasswordHasher = cryptotypes.PasswordHasher
	SecretHasher   = cryptotypes.SecretHasher
	Encryptor      = cryptotypes.Encryptor
	SigningKey     = cryptotypes.SigningKey
	Signer         = cryptotypes.Signer
	Randomizer     = cryptotypes.Randomizer

	JWTKind     = cryptotypes.JWTKind
	JWTConfig   = cryptotypes.JWTConfig
	Claims      = cryptotypes.Claims
	JWTProvider = cryptotypes.JWTProvider
	JWKKeyPair  = cryptotypes.JWKKeyPair
	JWKSStore   = cryptotypes.JWKSStore

	CSRFProtector   = cryptotypes.CSRFProtector
	OriginValidator = cryptotypes.OriginValidator

	SecretSource          = cryptotypes.SecretSource
	WatchableSecretSource = cryptotypes.WatchableSecretSource
)

const (
	KeyPurposePasswordHash  = cryptotypes.KeyPurposePasswordHash
	KeyPurposeTokenHash     = cryptotypes.KeyPurposeTokenHash
	KeyPurposeCookieSign    = cryptotypes.KeyPurposeCookieSign
	KeyPurposeEncryptAtRest = cryptotypes.KeyPurposeEncryptAtRest
	KeyPurposeJWTSign       = cryptotypes.KeyPurposeJWTSign

	JWTInternal = cryptotypes.JWTInternal
	JWTExternal = cryptotypes.JWTExternal
)
