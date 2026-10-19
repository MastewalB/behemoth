package crypto_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/MastewalB/behemoth/crypto"
	"github.com/MastewalB/behemoth/keysource"
	"github.com/golang-jwt/jwt/v5"
)

func ExampleVerifyJWT() {
	// An issuer's key, and its key set at a URL.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	set, err := crypto.MarshalJWKSet([]crypto.PublishedKey{{KID: "1", Algorithm: "EdDSA", Key: public}})
	if err != nil {
		log.Fatal(err)
	}
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(set) }))
	defer issuer.Close()

	// A token the issuer signed for the service.
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "https://auth.example.com", "aud": "https://api.example.com", "sub": "user-1",
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	})
	token.Header["kid"] = "1"
	signed, err := token.SignedString(private)
	if err != nil {
		log.Fatal(err)
	}

	// The service: the issuer's keys, fetched and kept, and the token
	// checked with them.
	source, err := keysource.NewJWKSet(nil, issuer.URL+"/.well-known/jwks.json")
	if err != nil {
		log.Fatal(err)
	}
	keys, err := crypto.NewCachedKeySet(source, crypto.CacheOptions{})
	if err != nil {
		log.Fatal(err)
	}
	verified, err := crypto.VerifyJWT(context.Background(), signed, keys, crypto.VerifyOptions{
		Issuers:   []string{"https://auth.example.com"},
		Audiences: []string{"https://api.example.com"},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(verified.Subject, verified.Algorithm)
	// Output: user-1 EdDSA
}
