package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
)

// The JWK codec turns a JWK set (RFC 7517) into the public keys tokens are
// verified with, and those keys into a JWK set to publish. It knows the key
// types of the JWS signature algorithms: RSA and EC on P-256, P-384 and
// P-521 (RFC 7518, section 6), and Ed25519 (RFC 8037). It does no I/O: a set
// that lives at a URL is fetched by a source, such as keysource.JWKSet
// (ADR-0003).

// minRSABits is the shortest RSA modulus the codec reads or writes.
const minRSABits = 2048

// jwk is one key of a JWK set, with the members of a public key (RFC 7518,
// section 6, and RFC 8037, section 2). A private key's members have no
// field, so a key written from a jwk can't carry one.
type jwk struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid,omitempty"`
	Use    string   `json:"use,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
	Alg    string   `json:"alg,omitempty"`
	Crv    string   `json:"crv,omitempty"`
	X      string   `json:"x,omitempty"`
	Y      string   `json:"y,omitempty"`
	N      string   `json:"n,omitempty"`
	E      string   `json:"e,omitempty"`
}

// ParseJWKSet reads a JWK set (RFC 7517, section 5) and returns its keys that
// can verify a signature, in the set's order.
//
// As RFC 7517 advises, a key that can't be used is left out, and the others
// are kept. That is a key of a type or on a curve the codec does not know, a
// symmetric key, a key whose "use" is not "sig" or whose "key_ops" lacks
// "verify", an "alg" the key can't sign with, an RSA key shorter than 2048
// bits or with an exponent crypto/rsa refuses, a point that is not on its
// curve, and a member that can't be decoded. A key that carries its private
// part ("d") is left out as well: a set that publishes a private key can't
// be trusted with it.
//
// A key that names no algorithm gets the one its type allows: ES256, ES384,
// or ES512 for an EC key, by its curve, and EdDSA for an Ed25519 key. An RSA
// key may sign with six, and keeps an empty Algorithm.
//
// Data that is not a JSON object with a "keys" array is an error. An empty
// set is not.
func ParseJWKSet(data []byte) ([]PublishedKey, error) {
	var set struct {
		Keys *[]json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("not a JWK set: %w", err)
	}
	if set.Keys == nil {
		return nil, errors.New(`not a JWK set: no "keys" array`)
	}
	keys := make([]PublishedKey, 0, len(*set.Keys))
	for _, raw := range *set.Keys {
		// Each key is decoded on its own, so that a malformed one is left
		// out and does not fail the set.
		if key, err := parseJWK(raw); err == nil {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// parseJWK reads one key of a set. Its error says why the key is left out.
func parseJWK(raw json.RawMessage) (PublishedKey, error) {
	var k jwk
	if err := json.Unmarshal(raw, &k); err != nil {
		return PublishedKey{}, err
	}
	var private struct {
		D json.RawMessage `json:"d"`
	}
	if err := json.Unmarshal(raw, &private); err != nil || private.D != nil {
		return PublishedKey{}, errors.New("the key carries its private part")
	}
	if k.Use != "" && k.Use != "sig" {
		return PublishedKey{}, fmt.Errorf("the key's use is %q", k.Use)
	}
	if len(k.KeyOps) > 0 && !slices.Contains(k.KeyOps, "verify") {
		return PublishedKey{}, errors.New(`the key's key_ops lack "verify"`)
	}
	key, err := k.publicKey()
	if err != nil {
		return PublishedKey{}, err
	}
	alg, algs := k.Alg, algorithmsOf(key)
	switch {
	case alg != "" && !slices.Contains(algs, alg):
		return PublishedKey{}, fmt.Errorf("the key can't sign with %q", alg)
	case alg == "" && len(algs) == 1:
		alg = algs[0]
	}
	return PublishedKey{KID: k.Kid, Algorithm: alg, Key: key}, nil
}

// publicKey decodes the key of k: an *rsa.PublicKey, an *ecdsa.PublicKey, or
// an ed25519.PublicKey.
func (k jwk) publicKey() (any, error) {
	switch k.Kty {
	case "RSA":
		n, err := unb64(k.N)
		if err != nil || len(n) == 0 {
			return nil, errors.New("RSA key: bad modulus")
		}
		e, err := unb64(k.E)
		if err != nil || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("RSA key: bad exponent")
		}
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if err := checkRSA(key); err != nil {
			return nil, err
		}
		return key, nil
	case "EC":
		curve, _, ok := curveNamed(k.Crv)
		if !ok {
			return nil, fmt.Errorf("EC key: curve %q", k.Crv)
		}
		size := (curve.Params().BitSize + 7) / 8
		x, errX := unb64(k.X)
		y, errY := unb64(k.Y)
		if errX != nil || errY != nil || len(x) == 0 || len(y) == 0 || len(x) > size || len(y) > size {
			return nil, errors.New("EC key: bad coordinates")
		}
		// The uncompressed point (SEC 1, section 2.3.3), which ecdsa refuses
		// when it is not on the curve. A coordinate shorter than the curve's
		// size, which some issuers write, is padded on the left.
		point := make([]byte, 1+2*size)
		point[0] = 4
		copy(point[1+size-len(x):1+size], x)
		copy(point[1+2*size-len(y):], y)
		key, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, fmt.Errorf("EC key: %w", err)
		}
		return key, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("OKP key: curve %q", k.Crv)
		}
		x, err := unb64(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("Ed25519 key: bad x")
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, fmt.Errorf("key type %q", k.Kty)
}

// MarshalJWKSet writes keys as a JWK set (RFC 7517, section 5), for a key set
// route. Each key is written with its kid, its algorithm when it names one,
// and use "sig". A key ParseJWKSet would leave out is an error, and so is a
// private key: only public halves are written.
func MarshalJWKSet(keys []PublishedKey) ([]byte, error) {
	set := struct {
		Keys []jwk `json:"keys"`
	}{Keys: make([]jwk, 0, len(keys))}
	for _, key := range keys {
		k, err := toJWK(key)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", key.KID, err)
		}
		set.Keys = append(set.Keys, k)
	}
	return json.Marshal(set)
}

func toJWK(key PublishedKey) (jwk, error) {
	if key.Algorithm != "" && !slices.Contains(algorithmsOf(key.Key), key.Algorithm) {
		return jwk{}, fmt.Errorf("a %T can't sign with %q", key.Key, key.Algorithm)
	}
	k := jwk{Kid: key.KID, Use: "sig", Alg: key.Algorithm}
	switch pub := key.Key.(type) {
	case *rsa.PublicKey:
		if pub == nil {
			break
		}
		if err := checkRSA(pub); err != nil {
			return jwk{}, err
		}
		k.Kty, k.N, k.E = "RSA", b64(pub.N.Bytes()), b64(big.NewInt(int64(pub.E)).Bytes())
		return k, nil
	case *ecdsa.PublicKey:
		if pub == nil {
			break
		}
		name, _, ok := curveName(pub.Curve)
		if !ok {
			return jwk{}, errors.New("EC key: a curve without a JWK name")
		}
		point, err := pub.Bytes()
		if err != nil {
			return jwk{}, fmt.Errorf("EC key: %w", err)
		}
		// The coordinates at the curve's full size, as RFC 7518 section
		// 6.2.1.2 requires.
		size := (len(point) - 1) / 2
		k.Kty, k.Crv, k.X, k.Y = "EC", name, b64(point[1:1+size]), b64(point[1+size:])
		return k, nil
	case ed25519.PublicKey:
		if len(pub) != ed25519.PublicKeySize {
			return jwk{}, errors.New("Ed25519 key: wrong size")
		}
		k.Kty, k.Crv, k.X = "OKP", "Ed25519", b64(pub)
		return k, nil
	}
	return jwk{}, fmt.Errorf("%T is not a public key the codec writes", key.Key)
}

// algorithmsOf returns the JWS algorithms key can verify (RFC 7518, section
// 3.1, and RFC 8037, section 3.1), and none for a key the codec does not
// know.
func algorithmsOf(key any) []string {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
	case *ecdsa.PublicKey:
		if k == nil {
			return nil
		}
		if _, alg, ok := curveName(k.Curve); ok {
			return []string{alg}
		}
	case ed25519.PublicKey:
		return []string{"EdDSA"}
	}
	return nil
}

// checkRSA refuses an RSA key the codec neither reads nor writes: one
// shorter than minRSABits, or with an exponent that is even, under 3, or
// over 2^31-1, which crypto/rsa refuses to verify with.
func checkRSA(key *rsa.PublicKey) error {
	if key.N == nil || key.N.BitLen() < minRSABits {
		return fmt.Errorf("RSA key: shorter than %d bits", minRSABits)
	}
	if key.E < 3 || key.E > 1<<31-1 || key.E%2 == 0 {
		return fmt.Errorf("RSA key: exponent %d", key.E)
	}
	return nil
}

// curveNamed returns the curve a JWK's "crv" names (RFC 7518, section
// 6.2.1.1), and the algorithm that signs with it (section 3.4).
func curveNamed(crv string) (elliptic.Curve, string, bool) {
	switch crv {
	case "P-256":
		return elliptic.P256(), "ES256", true
	case "P-384":
		return elliptic.P384(), "ES384", true
	case "P-521":
		return elliptic.P521(), "ES512", true
	}
	return nil, "", false
}

// curveName is curveNamed in reverse.
func curveName(curve elliptic.Curve) (string, string, bool) {
	switch curve {
	case elliptic.P256():
		return "P-256", "ES256", true
	case elliptic.P384():
		return "P-384", "ES384", true
	case elliptic.P521():
		return "P-521", "ES512", true
	}
	return "", "", false
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// unb64 decodes a base64url member (RFC 7515, section 2). Padding, which
// the format leaves out and some issuers write, is ignored.
func unb64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
