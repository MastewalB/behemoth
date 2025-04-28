package providers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// Apple implements the Provider interface for Sign in with Apple.
// Note: Sign in with Apple requires additional configuration like
// generating a client secret JWT. This basic implementation assumes
// the standard oauth2 flow is set up correctly.
type Apple struct {
	ProviderName string
	Config       *oauth2.Config
}

// NewApple creates a new Apple provider instance.
// Scopes typically include "name" and "email" to get user info in the ID token.
func NewApple(clientKey, secret, callbackURL string, scopes ...string) behemoth.Provider {
	if len(scopes) == 0 {
		scopes = DefaultAppleScope
	}
	return &Apple{
		ProviderName: "apple",
		Config: &oauth2.Config{
			ClientID:     clientKey, // This is the Services ID
			ClientSecret: secret,    // This is the generated client secret JWT
			RedirectURL:  callbackURL,
			Scopes:       scopes,
			Endpoint:     AppleEndpoint,
		},
	}
}

// appleIdTokenClaims represents the relevant claims in the Apple ID token.
// Ref: https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/authenticating_users_with_sign_in_with_apple
type appleIdTokenClaims struct {
	Email          string `json:"email"`
	EmailVerified  string `json:"email_verified"`   // "true" or "false"
	IsPrivateEmail string `json:"is_private_email"` // "true" or "false"
	// Name information might be requested separately via scope or form post
	// and isn't guaranteed in the token.
	jwt.RegisteredClaims
}

// appleName represents the name structure potentially received from Apple.
// This might come via form post during the initial authorization, not the token.
// type appleName struct {
// 	FirstName string `json:"firstName"`
// 	LastName  string `json:"lastName"`
// }

// Name returns the provider's name.
func (a *Apple) Name() string {
	return a.ProviderName
}

// GetEndpoint returns Apple's OAuth 2.0 endpoints.
func (a *Apple) GetEndpoint() oauth2.Endpoint {
	return AppleEndpoint
}

// GetConfig returns the oauth2 config for Apple.
func (a *Apple) GetConfig() *oauth2.Config {
	return a.Config
}

// GetScopes returns the scopes configured for Apple OAuth.
func (a *Apple) GetScopes() []string {
	return a.Config.Scopes
}

// FetchUserInfo for Apple attempts to parse the ID token received during the
// OAuth flow to extract user information.
// It does NOT make a separate call to a user info endpoint.
func (a *Apple) FetchUserInfo(client *http.Client, ctx context.Context, token *oauth2.Token) (models.UserInfo, error) {
	idTokenString, ok := token.Extra("id_token").(string)
	if !ok || idTokenString == "" {
		return models.UserInfo{}, fmt.Errorf("apple: id_token not found in token response")
	}

	// Parse the ID token without verification first to get claims.
	// Verification should happen earlier or requires Apple's public key.
	parser := jwt.NewParser()
	claims := &appleIdTokenClaims{}
	_, _, err := parser.ParseUnverified(idTokenString, claims)
	if err != nil {
		return models.UserInfo{}, fmt.Errorf("apple: failed to parse id_token: %w", err)
	}

	log.Printf("Apple ID Token Claims: Email=%s, Subject=%s", claims.Email, claims.Subject)

	// Name is often missing from the token itself, especially on subsequent logins.
	// It might be sent via POST request during the initial authorization flow.
	// Handling that requires changes outside this provider logic (e.g., in the callback handler).
	// We'll leave FirstName/LastName blank here.
	firstName := ""
	lastName := ""

	return models.UserInfo{
		Provider:          a.ProviderName,
		ID:                claims.Subject, // Apple's unique user identifier
		Email:             claims.Email,
		Name:              strings.TrimSpace(firstName + " " + lastName),
		FirstName:         firstName,
		LastName:          lastName,
		AvatarURL:         "", // Apple doesn't provide an avatar URL via token
		Location:          "", // Apple doesn't provide location via token
		AccessToken:       token.AccessToken,
		AccessTokenSecret: "",
		RefreshToken:      token.RefreshToken,
		ExpiresAt:         token.Expiry, // Expiry of the access token
		IDToken:           idTokenString,
	}, nil
}

// DefaultAppleScope specifies the default OAuth scopes for Sign in with Apple.
// Requesting name and email is crucial for getting user details on first login.
var DefaultAppleScope = []string{"name", "email"}

// AppleEndpoint defines the OAuth 2.0 endpoints for Sign in with Apple.
// Ref: https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/authenticating_users_with_sign_in_with_apple
var AppleEndpoint = oauth2.Endpoint{
	AuthURL:  "https://appleid.apple.com/auth/authorize",
	TokenURL: "https://appleid.apple.com/auth/token",
	// AuthStyle needs to be oauth2.AuthStyleInParams according to some docs,
	// as Apple expects client_id and client_secret in the POST body for token requests.
	// The default might work, but this is safer.
	AuthStyle: oauth2.AuthStyleInParams,
}

// Note: Apple does not have a standard user info endpoint like other providers.
// User info is primarily obtained from the ID token.
