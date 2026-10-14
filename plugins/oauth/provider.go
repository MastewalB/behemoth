package oauth

import (
	"context"
	"errors"
)

// ErrExchangeRefused is the error a Provider's Exchange returns, or wraps,
// when the sign-in can't be accepted: the provider refused the code, because
// it is unknown, expired, already redeemed or does not match the verifier or
// the redirect URI, or what the provider answered with did not pass the
// checks of the Provider, such as an ID token with another nonce. Complete
// then refuses the sign-in. Any other error of Exchange is taken as a failure
// of the system: the provider could not be reached, or its answer could not
// be read.
var ErrExchangeRefused = errors.New("oauth: the provider refused the sign-in")

// Provider is one OAuth 2.0 or OpenID Connect provider a user can sign in
// with, such as Google or GitHub. The plugin's flows call it and do the rest
// themselves: the state, the binding to the client, the lookup of the user
// and the session.
//
// The plugin creates a PKCE verifier and a nonce for every sign-in and hands
// them to the provider. Using them is the provider's part of the protocol,
// and the plugin can't check it: an implementation that ignores the code
// challenge leaves an authorization code that leaked unprotected.
//
// An implementation must be safe for concurrent use.
type Provider interface {
	// ID returns the provider's id, such as "google". It is the provider a
	// request names, the last segment of the provider's redirect URI
	// (RedirectURI) and the provider_id of the accounts it signs in, so it
	// does not change once users have signed in with it. It is made of
	// lowercase letters, digits, "-" and "_", starts with a letter or a
	// digit, and is not "credential".
	ID() string

	// AuthorizationURL returns the URL at the provider that the browser is
	// sent to for one sign-in. It is absolute, http or https.
	AuthorizationURL(ctx context.Context, req AuthorizationRequest) (string, error)

	// Exchange redeems the authorization code of one sign-in at the provider
	// and returns who signed in. The result has an Identity with a Subject.
	// An error that wraps ErrExchangeRefused refuses the sign-in, and any
	// other error is a failure of the system.
	Exchange(ctx context.Context, req ExchangeRequest) (*ExchangeResult, error)
}

// AuthorizationRequest is what the plugin created for one sign-in and a
// Provider puts into its authorization URL.
type AuthorizationRequest struct {
	// State is the value the provider returns with the authorization code.
	// It goes into the URL as it is.
	State string
	// RedirectURI is where the provider sends the browser back to: the
	// provider's redirect URI (RedirectURI).
	RedirectURI string
	// CodeChallenge is the PKCE challenge for the sign-in's verifier, made
	// with the S256 method.
	CodeChallenge string
	// Nonce is the value an OpenID Connect provider puts into the ID token.
	// A provider without ID tokens does not use it.
	Nonce string
}

// ExchangeRequest is what a Provider needs to redeem the authorization code
// of one sign-in.
type ExchangeRequest struct {
	// Code is the authorization code the provider sent with the state.
	Code string
	// RedirectURI is the redirect URI the authorization URL was made with.
	RedirectURI string
	// CodeVerifier is the PKCE verifier whose challenge was in the
	// authorization URL.
	CodeVerifier string
	// Nonce is the nonce that was in the authorization URL. An OpenID
	// Connect provider compares it with the one in the ID token.
	Nonce string
	// Issuer is the "iss" parameter the provider sent with the code (RFC
	// 9207), or empty when it sent none. A provider that knows its issuer
	// refuses another one, and refuses an empty one when it says it sends
	// the parameter.
	Issuer string
}

// ExchangeResult is what a Provider returns for a redeemed code.
//
// Not built: the provider's tokens. The plugin does not store them yet, so
// the result does not carry them.
type ExchangeResult struct {
	Identity Identity
}

// Identity is who a provider says signed in. It is plain data and holds no
// token.
type Identity struct {
	// Subject is the provider's id for the user: stable, unique at the
	// provider, and never reassigned. It becomes the account_id of the
	// user's account. An email address is not a subject.
	Subject string
	// Email is the user's address at the provider. It may be empty.
	Email string
	// EmailVerified reports whether the provider itself says it verified
	// Email. A provider that can't tell leaves it false.
	EmailVerified bool
	// Name is the user's full name, GivenName and FamilyName its parts.
	// Each may be empty.
	Name       string
	GivenName  string
	FamilyName string
	// Picture is the URL of the user's profile picture. It may be empty.
	Picture string
}
