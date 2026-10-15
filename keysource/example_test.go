package keysource_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/MastewalB/behemoth/keysource"
)

func ExampleJWKSet_Keys() {
	// A JWK set as an issuer serves it, here behemoth's own form of it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"1","use":"sig",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}`))
	}))
	defer srv.Close()

	source, err := keysource.NewJWKSet(nil, srv.URL+"/.well-known/jwks.json")
	if err != nil {
		log.Fatal(err)
	}
	keys, err := source.Keys(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	for _, k := range keys {
		fmt.Println(k.KID, k.Algorithm)
	}
	// Output: 1 EdDSA
}
