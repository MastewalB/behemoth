package crypto_test

import (
	"fmt"
	"log"

	"github.com/MastewalB/behemoth/crypto"
)

func ExampleParseJWKSet() {
	// The set of RFC 7517, appendix A.1. Its EC key is for encryption, so
	// it is left out.
	keys, err := crypto.ParseJWKSet([]byte(`{"keys":[
		{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"enc","kid":"1"},
		{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}
	]}`))
	if err != nil {
		log.Fatal(err)
	}
	for _, k := range keys {
		fmt.Printf("%s %s %T\n", k.KID, k.Algorithm, k.Key)
	}
	// Output: 2011-04-29 RS256 *rsa.PublicKey
}
