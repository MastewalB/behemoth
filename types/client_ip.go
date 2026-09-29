package types

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	behemotherr "github.com/MastewalB/behemoth/errors"
)

type ClientIPConfig struct {
	trustedNets []*net.IPNet
	header      string
}

// NewClientIPConfig parses trustedProxies (CIDR blocks, the reverse proxies/
// load balancers allowed to set forwarding headers) once at boot. header
// defaults to "X-Forwarded-For".
func NewClientConfig(trustedProxies []string, header string) (*ClientIPConfig, error) {
	if header == "" {
		header = "X-Forwarded-For"
	}

	nets := make([]*net.IPNet, 0, len(trustedProxies))
	for _, cidr := range trustedProxies {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, behemotherr.NewConfigurationError("ClientIP.Config", fmt.Sprintf("invalid trusted proxy CIDR %q", cidr), err)
		}
		nets = append(nets, n)
	}
	return &ClientIPConfig{trustedNets: nets, header: header}, nil
}

func (c *ClientIPConfig) IsTrusted(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, n := range c.trustedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP resolves the real client address defensively:
//   - If the DIRECT connection (r.RemoteAddr) isn't itself from a trusted
//     proxy, the forwarding header is IGNORED ENTIRELY — anyone can set
//     X-Forwarded-For on a raw request, so trusting it from an untrusted
//     peer is a direct rate-limit-bypass vector (attacker sets a fresh IP
//     per request, sails past a per-IP limit for free).
//   - If the direct peer IS trusted, walk the header's comma-separated chain
//     from the RIGHT (closest hop to us) and return the first entry that
//     is NOT itself a trusted proxy — i.e. the nearest untrusted hop, which
//     is the real client as far as our infrastructure can vouch for.
func ClientIP(r *http.Request, cfg *ClientIPConfig) string {
	remote, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remote = r.RemoteAddr // no port present — use as-is
	}
	if len(cfg.trustedNets) == 0 || !cfg.IsTrusted(remote) {
		return remote
	}
	value := r.Header.Get(cfg.header)
	if value == "" {
		return remote
	}
	parts := strings.Split(value, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		if !cfg.IsTrusted(candidate) {
			return candidate
		}
	}
	return remote // every hop in the chain was a trusted proxy — degrade to the direct peer

}
