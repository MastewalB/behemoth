package outbound_test

import (
	"testing"

	"github.com/MastewalB/behemoth/outbound"
	"github.com/stretchr/testify/assert"
)

// A credential or a key goes to an absolute https URL, or to http on a
// loopback address, and never to a URL with credentials or a fragment.
func TestCheckURL(t *testing.T) {
	for _, raw := range []string{
		"https://login.example.com/token", "https://login.example.com/authorize?prompt=select_account",
		"http://localhost:8080/realms/dev", "http://127.0.0.1/token", "http://127.8.9.1/token", "http://[::1]:9000/token",
	} {
		assert.NoError(t, outbound.CheckURL(raw), raw)
	}
	for _, raw := range []string{
		"http://login.example.com/token", "http://localhost.example.com/token", "http://10.0.0.1/token",
		"/token", "login.example.com/token", "ftp://login.example.com/token", "",
		"https://client:secret@login.example.com/token", "https://login.example.com/token#frag", "https://[::1/token",
	} {
		assert.Error(t, outbound.CheckURL(raw), raw)
	}
}
