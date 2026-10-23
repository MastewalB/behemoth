package oauth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/errs"
	"github.com/go-behemoth/behemoth/httpapi"
	"github.com/go-behemoth/behemoth/utils"
)

// Paths of the plugin's routes, below the router's base path.
const (
	// PathBegin starts a sign-in: Begin.
	PathBegin = "/sign-in/oauth"
	// PathComplete finishes it: Complete.
	PathComplete = "/oauth/complete"
)

// RuleBeginAddress is the name of the rate-limit rule on sign-ins started,
// per client address. RateLimitConfig.Limits and Disabled change it by name.
// Completions are sign-ins, which core's core.signin.address counts per
// client address and method.
const RuleBeginAddress = "oauth.begin.address"

// Keys of the routes' bodies that are not keys of a hook payload.
const (
	keyAuthorizationURL = "authorization_url"
	keyBinding          = "binding"
	keyCode             = "code"
	keyState            = "state"
	keyIssuer           = "iss"
)

// BindingCookiePrefix starts the name of the cookie that holds the binding
// value of a sign-in under the cookie deliveries. The rest of the name is
// derived from the sign-in's state, so two sign-ins started in one browser
// keep a cookie each. With RouterConfig.Carrier.CookieInsecure off, the
// default, the name also starts with "__Host-": a browser then accepts the
// cookie only over HTTPS and only from the host it is sent to.
const BindingCookiePrefix = "behemoth_oauth_"

// handleBegin answers with the URL to send the browser to. The binding value
// goes where the session token goes: into an HttpOnly cookie under the
// cookie deliveries, and into the body for a client that keeps the session
// token itself. Under DeliveryBoth it goes to both.
//
//	{"authorization_url": "https://..."}
//	{"authorization_url": "https://...", "binding": "..."}
func (p *Plugin) handleBegin(rctx *httpapi.RequestContext) error {
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil {
		return errs.NewValidationError("oauth.Begin", "request", err)
	}
	var req BeginRequest
	if err := req.FromMap(body); err != nil {
		return err
	}

	result, err := p.Begin(rctx.Ctx, req)
	if err != nil {
		return err
	}

	cfg := rctx.TokenCarrier.Config()
	answer := behemoth.M{keyAuthorizationURL: result.AuthorizationURL}
	if cfg.Delivery.ReadsCookie() {
		rctx.Response.Cookie(bindingCookie(cfg, result.State, result.Binding, time.Until(result.ExpiresAt)))
	}
	if cfg.Delivery != httpapi.DeliveryCookie {
		answer[keyBinding] = result.Binding
	}
	// The URL holds the state, and the body may hold the binding value.
	rctx.Response.SetHeader("Cache-Control", "no-store")
	return rctx.Response.JSON(http.StatusOK, answer)
}

// handleComplete takes the binding value from the body, and under the
// cookie deliveries from the sign-in's cookie when the body has none. It
// answers like every sign-in route (httpapi.WriteSignIn), with the redirect
// target next to the user, and removes the cookie once the sign-in is done.
// A refused callback is the flow's typed error, which the router maps.
func (p *Plugin) handleComplete(rctx *httpapi.RequestContext) error {
	const op = "oauth.Complete"
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil {
		return errs.NewValidationError(op, "request", err)
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
			return errs.NewInvalidInputError(op, field.key, field.key+" must be a string", nil)
		}
	}

	cfg := rctx.TokenCarrier.Config()
	if req.Binding == "" && req.State != "" && cfg.Delivery.ReadsCookie() {
		if cookie, err := rctx.Request.Cookie(bindingCookieName(cfg, req.State)); err == nil {
			req.Binding = cookie.Value
		}
	}

	result, err := p.Complete(rctx.Ctx, req)
	if err != nil {
		return err
	}
	if cfg.Delivery.ReadsCookie() {
		// The state is used up, and its binding value with it.
		rctx.Response.Cookie(bindingCookie(cfg, req.State, "", -1))
	}
	return httpapi.WriteSignIn(rctx, result.SignInResult, behemoth.M{keyRedirectURL: result.RedirectURL})
}

// bindingCookieName returns the name of the cookie for the sign-in with
// state. It carries 16 hex characters of the state's SHA-256 and not the
// state, which is a URL's to carry.
func bindingCookieName(cfg httpapi.TokenCarrierConfig, state string) string {
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
func bindingCookie(cfg httpapi.TokenCarrierConfig, state, value string, maxAge time.Duration) *http.Cookie {
	seconds := int(maxAge / time.Second)
	if seconds <= 0 {
		seconds = -1 // Max-Age=0: remove it
	}
	return &http.Cookie{
		Name: bindingCookieName(cfg, state), Value: value, Path: "/", MaxAge: seconds,
		HttpOnly: true, Secure: !cfg.CookieInsecure, SameSite: cfg.CookieSameSite.HTTP(),
	}
}
