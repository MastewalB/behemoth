package outbound

import (
	"fmt"
	"net"
	"net/url"
)

// CheckURL returns an error for a URL that behemoth should not send a
// credential to, nor fetch a key from: one that is not absolute, carries
// credentials or a fragment, or is not https. Plain http is allowed on a
// loopback address (localhost, 127.0.0.0/8, ::1), for a service in
// development.
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	switch {
	case u.Host == "" || u.User != nil || u.Fragment != "":
		return fmt.Errorf("%q is not an absolute URL without credentials or a fragment", raw)
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && isLoopback(u.Hostname()):
		return nil
	}
	return fmt.Errorf("%q is not https", raw)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
