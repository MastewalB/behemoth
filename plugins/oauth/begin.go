package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/core"
	"github.com/go-behemoth/behemoth/errs"
	"github.com/go-behemoth/behemoth/store"
	"github.com/go-behemoth/behemoth/telemetry"
	"github.com/go-behemoth/behemoth/utils"
)

// Keys of Begin's hook payload.
const (
	keyProvider    = "provider"
	keyRedirectURL = "redirect_url"
)

// Keys of the metadata a started sign-in is kept with, on its oauth_state
// token. Handlers on the token points see the metadata, so the two secrets
// are not in it as they are: the verifier is sealed, and of the binding
// value only the hash is kept.
const (
	metaProvider    = "provider"
	metaRedirectURL = "redirect_url"
	metaNonce       = "nonce"
	metaVerifier    = "verifier_secret"
	metaBindingHash = "binding_hash"
)

// verifierBinding binds the sealed verifier of a sign-in to the hash of its
// binding value, kept beside it. The token's id would be the obvious owner,
// but the verifier is sealed before the token exists.
func verifierBinding(bindingHash string) store.SealBinding {
	return store.SealBinding{Purpose: "oauth.pkce_verifier", Owner: bindingHash}
}

// BeginRequest is the input of Begin.
//
// It implements [behemoth.Serializable]. The auth.oauth.beforeBegin payload
// is flat: "provider", "redirect_url" and the keys of Extra.
type BeginRequest struct {
	// Provider is the id of the provider to sign in with (Provider.ID).
	Provider string
	// RedirectURL is where the application should send the user after the
	// sign-in. Optional. It has to be a path on the application's own site
	// or a URL on one of RouterConfig.TrustedOrigins.
	RedirectURL string
	// Extra holds input that only handlers on auth.oauth.beforeBegin read,
	// such as a captcha token. The plugin does not read or store it.
	Extra behemoth.M
}

// ToMap returns the request as a hook payload.
func (r *BeginRequest) ToMap() (map[string]any, error) {
	m := make(map[string]any, len(r.Extra)+2)
	for k, v := range r.Extra {
		m[k] = v
	}
	m[keyProvider], m[keyRedirectURL] = r.Provider, r.RedirectURL
	return m, nil
}

// FromMap sets the request from a request body or a rewritten payload:
// "provider" and "redirect_url" fill the fields, and every other key goes to
// Extra, which is replaced. A missing key leaves its field empty. A provider
// or a redirect URL that is not a string is a validation error.
func (r *BeginRequest) FromMap(data map[string]any) error {
	const op = "oauth.Begin"
	field := func(key string) (string, error) {
		switch v := data[key].(type) {
		case nil:
			return "", nil
		case string:
			return v, nil
		default:
			return "", errs.NewInvalidInputError(op, key, key+" must be a string", nil)
		}
	}
	provider, err := field(keyProvider)
	if err != nil {
		return err
	}
	redirect, err := field(keyRedirectURL)
	if err != nil {
		return err
	}
	var extra behemoth.M
	for k, v := range data {
		if k == keyProvider || k == keyRedirectURL {
			continue
		}
		if extra == nil {
			extra = behemoth.M{}
		}
		extra[k] = v
	}
	r.Provider, r.RedirectURL, r.Extra = provider, redirect, extra
	return nil
}

// BeginResult is what Begin returns. Handlers on auth.oauth.afterBegin
// receive it without AuthorizationURL, State and Binding.
type BeginResult struct {
	// Provider is the id of the provider the sign-in is with.
	Provider string
	// TransactionID is the id of the token the sign-in is kept as.
	TransactionID string
	// AuthorizationURL is the URL at the provider to send the browser to.
	AuthorizationURL string
	// State is the state of the sign-in, which is also in AuthorizationURL.
	// The provider returns it with the code, and Complete takes it back.
	State string
	// Binding ties the sign-in to the client that started it: finishing the
	// sign-in takes this value next to the state, and only its hash is kept.
	// The caller hands it to that client, and to nobody else, in a place a
	// URL does not reach: an HttpOnly cookie, or the client's own storage.
	Binding string
	// ExpiresAt is when the sign-in can no longer be finished.
	ExpiresAt time.Time
}

// Begin starts a sign-in with the provider req.Provider. It creates the
// state, the PKCE verifier, the nonce and the binding value of the sign-in,
// keeps them as a single-use token, and returns the provider's authorization
// URL with the binding value. Complete finishes the sign-in. Begin fires
// auth.oauth.beforeBegin, .afterBegin and .beginFailed.
//
// A provider the plugin was not configured with and a redirect URL outside
// the trusted origins are validation errors. An error of the provider is
// returned as a failure of the system, and the sign-in it was for is ended.
//
// Pass the context of the request being handled when there is one. The
// plugin must have been initialized by Boot.
func (p *Plugin) Begin(ctx context.Context, req BeginRequest) (*BeginResult, error) {
	hctx, err := p.operation(ctx, "oauth.Begin")
	if err != nil {
		return nil, err
	}
	// One operation: the three points and the token write share Values.
	hctx = core.AsOperation(hctx)
	dispatcher := p.authContext.Dispatcher

	payload, err := req.ToMap()
	if err != nil {
		return nil, err
	}
	payload, err = dispatcher.RunBefore(hctx, HookBeginBefore, payload)
	if err != nil {
		return nil, core.FailIfRejected(dispatcher, hctx, HookBeginFailed, err, core.FailureReason{})
	}
	if err := req.FromMap(payload); err != nil {
		return nil, err
	}

	result, err := p.beginBody(hctx, req)
	if err != nil {
		return nil, err
	}

	// Handlers learn that a sign-in started, and not what finishes it.
	started := *result
	started.AuthorizationURL, started.State, started.Binding = "", "", ""
	if err := dispatcher.RunAfter(hctx, HookBeginAfter, &started); err != nil {
		return nil, err
	}
	return result, nil
}

func (p *Plugin) beginBody(hctx *core.HookContext, req BeginRequest) (*BeginResult, error) {
	const op = "oauth.Begin"
	ac := hctx.Auth

	provider, ok := p.providers[req.Provider]
	if !ok {
		return nil, errs.NewInvalidInputError(op, keyProvider, "unknown provider", nil)
	}
	if req.RedirectURL != "" && !core.TrustedRedirect(ac.Origins, req.RedirectURL) {
		return nil, errs.NewInvalidInputError(op, keyRedirectURL, "redirect URL is not allowed", nil)
	}

	// 32 random bytes each. As base64url that is 43 characters, which is
	// also a valid PKCE verifier (RFC 7636, section 4.1).
	var verifier, nonce, binding string
	for _, secret := range []*string{&verifier, &nonce, &binding} {
		value, err := ac.Crypto.Random.SecureRandomString(32)
		if err != nil {
			return nil, errs.NewSecurityError(op, "random_generation_failed", err)
		}
		*secret = value
	}
	bindingHash := utils.LookupHashOf(binding)
	sealedVerifier, err := ac.Store.Seal(verifier, verifierBinding(bindingHash))
	if err != nil {
		return nil, err
	}

	meta := behemoth.M{
		metaProvider:    provider.ID(),
		metaNonce:       nonce,
		metaVerifier:    sealedVerifier,
		metaBindingHash: bindingHash,
	}
	if req.RedirectURL != "" {
		meta[metaRedirectURL] = req.RedirectURL
	}
	// The raw token is the state. The token has no subject: nobody is
	// signed in yet. Not built: a sign-in that links a provider account to
	// the signed-in user, whose token would name that user.
	token, state, err := ac.TokenManager.Issue(hctx.Ctx, core.TokenKindOAuthState, nil, meta)
	if err != nil {
		// A handler or a rate limit on token.beforeIssue may have refused.
		return nil, core.FailIfRejected(ac.Dispatcher, hctx, HookBeginFailed, err, core.FailureReason{})
	}

	authorizationURL, err := provider.AuthorizationURL(hctx.Ctx, AuthorizationRequest{
		State:         state,
		RedirectURI:   RedirectURI(p.opts.CallbackURL, provider.ID()),
		CodeChallenge: challengeS256(verifier),
		Nonce:         nonce,
	})
	if err == nil {
		err = checkAuthorizationURL(authorizationURL)
	}
	if err != nil {
		// A sign-in no browser was sent to should not stay open.
		if revokeErr := ac.TokenManager.Revoke(hctx.Ctx, token.ID); revokeErr != nil {
			p.log.Warn(hctx.Ctx, "the sign-in that could not be started was not ended", telemetry.ErrorFields(revokeErr))
		}
		return nil, fmt.Errorf("oauth: authorization URL of provider %q: %w", provider.ID(), err)
	}

	return &BeginResult{
		Provider:         provider.ID(),
		TransactionID:    token.ID,
		AuthorizationURL: authorizationURL,
		State:            state,
		Binding:          binding,
		ExpiresAt:        token.ExpiresAt,
	}, nil
}

// challengeS256 returns the PKCE code challenge of verifier for the S256
// method: the base64url of its SHA-256, without padding (RFC 7636, section
// 4.2).
func challengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// checkAuthorizationURL refuses what a provider returned when a browser
// could not be sent there: the client navigates to the URL as it is. The
// error does not quote the URL, which holds the state.
func checkAuthorizationURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("not an absolute http or https URL")
	}
	return nil
}
