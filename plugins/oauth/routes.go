package oauth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/utils"
)

// Paths of the plugin's routes, below the router's base path.
const (
	// PathBegin starts a sign-in: Begin.
	PathBegin = "/sign-in/oauth"
	// PathComplete finishes it: Complete.
	PathComplete = "/oauth/complete"
)

// Names of the rate-limit rules the plugin declares. An application that
// wants another limit declares a more specific rule, or the same method and
// path with Disabled set.
const (
	RuleBeginRoute    = "oauth.begin.route"    // sign-ins started per client address
	RuleCompleteRoute = "oauth.complete.route" // completions tried per client address
)

// Keys of the routes' bodies that are not keys of a hook payload.
const (
	keyAuthorizationURL = "authorization_url"
	keyBinding          = "binding"
	keyCode             = "code"
	keyState            = "state"
	keyIssuer           = "iss"
)

// BindingCookiePrefix starts the name of the cookie that holds the binding
// value of a sign-in under the cookie transports. The rest of the name is
// derived from the sign-in's state, so two sign-ins started in one browser
// keep a cookie each. With SessionConfig.CookieInsecure off, the default,
// the name also starts with "__Host-": a browser then accepts the cookie
// only over HTTPS and only from the host it is sent to.
const BindingCookiePrefix = "behemoth_oauth_"

// handleBegin answers with the URL to send the browser to. The binding value
// goes where the session token goes: into an HttpOnly cookie under the
// cookie transports, and into the body for a client that keeps the session
// token itself. Under TransportBoth it goes to both.
//
//	{"authorization_url": "https://..."}
//	{"authorization_url": "https://...", "binding": "..."}
func (p *Plugin) handleBegin(rctx *types.RequestContext) error {
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil {
		return behemotherr.NewValidationError("oauth.Begin", "request", err)
	}
	var req BeginRequest
	if err := req.FromMap(body); err != nil {
		return err
	}

	result, err := p.Begin(rctx.Ctx, req)
	if err != nil {
		return err
	}

	cfg := rctx.Auth.SessionConfig
	answer := behemoth.M{keyAuthorizationURL: result.AuthorizationURL}
	if cfg.Transport.ReadsCookie() {
		rctx.Response.Cookie(bindingCookie(cfg, result.State, result.Binding, time.Until(result.ExpiresAt)))
	}
	if cfg.Transport != types.TransportCookie {
		answer[keyBinding] = result.Binding
	}
	// The URL holds the state, and the body may hold the binding value.
	rctx.Response.SetHeader("Cache-Control", "no-store")
	return rctx.Response.JSON(http.StatusOK, answer)
}

// handleComplete takes the binding value from the body, and under the
// cookie transports from the sign-in's cookie when the body has none. It
// answers like every sign-in route (types.WriteSignIn), with the redirect
// target next to the user, and removes the cookie once the sign-in is done.
// A refused callback is the flow's typed error, which the router maps.
func (p *Plugin) handleComplete(rctx *types.RequestContext) error {
	const op = "oauth.Complete"
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil {
		return behemotherr.NewValidationError(op, "request", err)
	}
	var req CompleteRequest
	for _, field := range []struct {
		key  string
		into *string
	}{
		{keyProvider, &req.Provider}, {keyCode, &req.Code}, {keyState, &req.State}, {keyBinding, &req.Binding},
		{keyIssuer, &req.Issuer},
	} {
		switch v := body[field.key].(type) {
		case nil:
		case string:
			*field.into = v
		default:
			return behemotherr.NewInvalidInputError(op, field.key, field.key+" must be a string", nil)
		}
	}

	cfg := rctx.Auth.SessionConfig
	if req.Binding == "" && req.State != "" && cfg.Transport.ReadsCookie() {
		if cookie, err := rctx.Request.Cookie(bindingCookieName(cfg, req.State)); err == nil {
			req.Binding = cookie.Value
		}
	}

	result, err := p.Complete(rctx.Ctx, req)
	if err != nil {
		return err
	}
	if cfg.Transport.ReadsCookie() {
		// The state is used up, and its binding value with it.
		rctx.Response.Cookie(bindingCookie(cfg, req.State, "", -1))
	}
	return types.WriteSignIn(rctx, result.SignInResult, behemoth.M{keyRedirectURL: result.RedirectURL})
}

// bindingCookieName returns the name of the cookie for the sign-in with
// state. It carries 16 hex characters of the state's SHA-256 and not the
// state, which is a URL's to carry.
func bindingCookieName(cfg types.SessionConfig, state string) string {
	name := BindingCookiePrefix + utils.LookupHashOf(state)[:16]
	if !cfg.CookieInsecure {
		// Secure, Path "/" and no Domain, which the prefix requires: a
		// sibling subdomain can't set a cookie of this name, so it can't
		// plant its own binding value in a victim's browser.
		name = "__Host-" + name
	}
	return name
}

// bindingCookie returns the cookie that holds value for the sign-in with
// state, for maxAge. A maxAge of zero or less removes the cookie. SameSite
// and Secure follow the session cookie: the cookie has to reach the
// complete route on the same requests the session cookie reaches.
func bindingCookie(cfg types.SessionConfig, state, value string, maxAge time.Duration) *http.Cookie {
	sameSite := http.SameSiteLaxMode
	switch cfg.CookieSameSite {
	case types.SameSiteStrict:
		sameSite = http.SameSiteStrictMode
	case types.SameSiteNone:
		sameSite = http.SameSiteNoneMode
	}
	seconds := int(maxAge / time.Second)
	if seconds <= 0 {
		seconds = -1 // Max-Age=0: remove it
	}
	return &http.Cookie{
		Name: bindingCookieName(cfg, state), Value: value, Path: "/", MaxAge: seconds,
		HttpOnly: true, Secure: !cfg.CookieInsecure, SameSite: sameSite,
	}
}
