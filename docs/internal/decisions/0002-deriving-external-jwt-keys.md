# 0002. Derive the signing keys of external JWTs from the master secret

- **Status:** Proposed
- **Date:** 2026-10-14
- **Deciders:** MastewalB
- **Affects:** `crypto` (`jwt.go`, `jwks_store.go`, `key_manager.go`), `types/cryptotypes` (`JWKSStore`, `JWKKeyPair`, `KeyPurpose`), `types/init` (`Boot`, `CoreDeclareSchema`)

## Context and problem

`crypto.JWTProviderImpl` issues two kinds of JWT. An internal JWT is HS256, signed with a key the `KeyManager` derives from the master secret: HKDF-SHA256 over the secret of a version, with the key's purpose (`jwt_sign`) as the info. Its `kid` is the secret's version. Nothing is stored, and a rotation of the master secret rotates it.

An external JWT is EdDSA, for other services to verify with the published key set. Its key pairs are generated at random by `JWKSStore.Rotate` and kept in the `jwk_keypairs` table, with the private key encrypted by a key the `KeyManager` derives (`encrypt_at_rest`). The comment on `JWKKeyPair` says why: "asymmetric keypairs don't derive from a master secret via HKDF, so they must be generated once and stored".

That reason does not hold. An Ed25519 private key is fully determined by a 32-byte seed (`ed25519.NewKeyFromSeed`, RFC 8032), and the `KeyManager` already derives 32 bytes per purpose and version.

Storing the pairs costs more than the table. External JWTs can't be wired into `Boot` without answering the questions it raises:

- **The table** has to be declared, migrated, and kept in step on every database the store supports.
- **The first key** does not exist until `Rotate` has run once. Something has to run it before the first external token is signed.
- **Replicas** that start together can each create a first key.
- **Rotation** needs a schedule of its own, which the application has to own (`service_ready_components.md`, "Background work is a method first").

The interface between the provider and its keys has a second problem. `JWKSStore` hands the provider a `JWKKeyPair` with the private key in it, encrypted, and the provider decrypts it and signs. A key whose private half never leaves its holder, such as a key in a KMS or an HSM, can't be handed over, so it can't implement `JWKSStore`.

## Decision drivers

In priority order:

1. A third party keeps verifying a token across a rotation, until the token expires.
2. No state that has to be created, migrated or coordinated between replicas before Behemoth can sign.
3. One root of trust that operators already protect and rotate: the master secret in the `SecretSource`.
4. Room for a key held by a KMS later, without changing the provider or its callers.

## Options considered

### Option A: random key pairs in `jwk_keypairs` (as built)
`Rotate` generates a pair and stores it encrypted. The active pair signs, and every pair is published.
- **Pros:** the external keys rotate on a schedule of their own, independent of the master secret. Reading the master secret is not enough to sign: an attacker also needs a row of the table.
- **Cons:** the table, the first key, the race between replicas, and a rotation the application has to schedule. The second barrier is thin: the master secret decrypts the rows.
- **Fails when:** a deployment starts several replicas at once on an empty table, or nobody schedules `Rotate`. Signing fails until a key exists.

### Option B: key pairs derived from the master secret
A new purpose, `jwt_external`, derives a 32-byte seed per secret version. The seed is the Ed25519 private key. The `kid` is the version. The published key set is the public key of every version the `SecretSource` holds.
- **Pros:** no table, no first key, no race: every replica derives the same keys. A rotation of the master secret rotates the external keys too, with the same overlap: a version stays in the source until the tokens it signed have expired.
- **Cons:** one cadence for every derived key: cookie signing, token hashing, encryption at rest, and both JWT kinds rotate together. Whoever reads the master secret can sign external tokens.
- **Fails when:** an operator needs the external keys to rotate at another pace than the master secret, or a policy requires signing keys to be held by a KMS or an HSM.

### Option C: a KMS-held key from the start
The provider signs through a KMS client, and publishes the KMS's public key.
- **Pros:** the private key never exists in Behemoth's memory.
- **Cons:** a cloud dependency for every deployment, in the root module or behind an interface that nothing else implements yet. KMS key types differ between providers, and some offer ECDSA or RSA and not Ed25519. Most deployments don't need it.
- **Fails when:** the application has no KMS, which is the common case.

## Decision

We chose Option B, and with it a new interface between the provider and its keys, so that Option C stays possible as a second implementation.

The interface signs instead of handing out private keys. It is `types.ExternalKeySet` (`types/cryptotypes`):

```go
type ExternalKeySet interface {
	// CurrentKey returns the key new tokens are signed with, fixed for one
	// token: its id and algorithm go into the header, which is signed with
	// the claims.
	CurrentKey(ctx context.Context) (ExternalSigningKey, error)
	// PublicKey returns the key kid names, to verify a token with. An
	// unknown kid is a refused token.
	PublicKey(ctx context.Context, kid string) (PublishedKey, error)
	// PublicKeys returns every key a verifier may still need, to publish.
	PublicKeys(ctx context.Context) ([]PublishedKey, error)
}

type ExternalSigningKey interface {
	KID() string
	Algorithm() string
	Sign(ctx context.Context, payload []byte) ([]byte, error)
}
```

The key is fixed before the token is encoded because the header, with the key's id and algorithm, is part of what is signed.

The derived key set is its first implementation. `JWKSStore`, `JWKKeyPair`, `dbJWKSStore`, `NewJWKSStore` and the `jwk_keypairs` table are removed.

## Rationale

Option B meets drivers 1 to 3 with less code than Option A has today. Rotation already works the way driver 1 asks: the `KeyManager` keeps every version the `SecretSource` holds, and the internal JWT verifies across a rotation this way.

Option A loses on driver 2, and its advantage on driver 3 is small. The master secret decrypts its rows, so separating the keys from the master secret only adds a database read for an attacker who already has the secret.

Option C loses on its cost for every deployment, while it is needed by few. The interface keeps it open (driver 4) for those that need it, at the price of one interface that has one implementation until then.

## Consequences

- **Gains:**
  - external JWTs can be wired into `Boot` with no table, no migration and no first key;
  - every replica signs and verifies with the same keys without coordinating;
  - one rotation procedure for every key.
- **Costs and risks we accepted:**
  - the external keys can't rotate apart from the master secret;
  - the master secret alone is enough to sign external tokens;
  - removing a secret version from the `SecretSource` also stops the external tokens it signed from verifying. The tokens are short-lived (see the issuance design), so a version kept for the longest TTL is enough.
- **Follow-up work:**
  - add `KeyPurposeJWTExternal`;
  - define `ExternalKeySet` and implement it over the `KeyManager`;
  - move `externalJWT` to the interface, with the algorithm taken from the key and never from the token's header;
  - publish one key per version;
  - remove `JWKSStore`, `JWKKeyPair`, `dbJWKSStore`, the `jwk_keypairs` column constants, and `tests/store/jwks_store_test.go`. `crypto/jwt_test.go` keeps its expectations, with its in-memory key set moved to the new interface.

## Invariants

- **The purpose string `jwt_external` never changes.** It is the HKDF info. A changed string changes every external key, and every token issued before stops verifying.
- **The seed is the HKDF output, as it is.** Ed25519 accepts any 32 bytes as a seed, so no step in between is needed, and adding one changes every key.
- **The `kid` of a derived key is the secret's version, as a decimal string**, as for internal tokens. A verifier looks the key up by it.
- **The algorithm of a token comes from the key its `kid` names, never from the token's header.** A key set that holds keys of several algorithms is still safe from algorithm confusion.
- **A private key never leaves an `ExternalKeySet`.** The provider asks it to sign. This is what lets a KMS key set exist.

## A key held by a KMS, later

The steps for a deployment that needs a KMS or HSM key:

1. **A key set in a module of its own,** such as `crypto/adapters/awskms`, so that the root module does not gain a cloud SDK (`service_ready_components.md`, "A new dependency gets a module of its own"). It implements `ExternalKeySet`: `Sign` calls the KMS, `PublicKey` and `PublicKeys` return the public keys the KMS reports, cached, with the key's version or ARN as the `kid`.
2. **The algorithm the KMS offers.** Some offer ECDSA (ES256) or RSA (RS256, PS256) and not Ed25519. The key set names the algorithm of each key, and the provider checks a token against it, from an allowlist of asymmetric algorithms. A key set that offers no allowed algorithm fails at `Boot`.
3. **A setting to choose it.** `BootConfig` takes an `ExternalKeySet` in place of the derived one. The key set is code, so a configuration file names it by a kind, as the OAuth plugin's built-in providers are named (`docs/internal/plugins/oauth.md`).
4. **A move without a gap.** A key set that combines two others signs with the KMS and publishes the keys of both. Tokens signed with the derived keys keep verifying until they expire, and the derived keys are dropped after that.

Nothing of the derived key set changes for this, and nothing of the provider beyond what the follow-up work already makes generic.

## Revisit when

- An operator asks for the external keys to rotate apart from the master secret. Option A or C would then be needed, and the interface is where it goes.
- A compliance requirement says signing keys must be held by a KMS or an HSM. Build the module of the section above.
- A verifier is found that can't follow a key whose `kid` is a small integer. A key id derived from the public key, such as an RFC 7638 thumbprint, would replace it.

## References

- `crypto/key_manager.go`: `deriveKey`, the HKDF this decision reuses
- `crypto/jwt.go`: `externalJWT`, which moves to the new interface
- RFC 8032, section 5.1.5: an Ed25519 key is generated from a 32-byte seed
- RFC 7517: the JSON Web Key Set format the published keys use
- [`../plans/session_tokens.md`](../plans/session_tokens.md): the session tokens these keys sign
