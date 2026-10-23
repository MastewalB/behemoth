package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/core"
	"github.com/go-behemoth/behemoth/errs"
)

// PathSessionToken is the route that exchanges the caller's session for a
// session token: POST, below the router's base path.
const PathSessionToken = "/session/token"

// SessionTokenRoutes returns POST /session/token, which exchanges the
// caller's session for a session token through tokens. Boot mounts it below
// the base path when session tokens are on, that is when
// crypto.JWTConfig names an external audience.
func SessionTokenRoutes(tokens core.SessionTokens) []Route {
	// No session middleware: Issue requires the caller itself.
	return []Route{{Method: http.MethodPost, Path: PathSessionToken, Handler: sessionTokenHandler(tokens)}}
}

// sessionTokenHandler answers with the token, its expiry and its audience.
// The body is optional: an empty one asks for the default audience.
//
//	{"token": "...", "expires_at": "2026-10-14T10:15:00Z", "audience": "https://api.example.com"}
func sessionTokenHandler(tokens core.SessionTokens) HandlerFunc {
	return func(rctx *RequestContext) error {
		const op = "SessionTokens.Issue"
		var body behemoth.M
		if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			return errs.NewValidationError(op, "request", err)
		}
		audience, ok := body[core.SessionTokenAudienceKey].(string)
		if !ok && body[core.SessionTokenAudienceKey] != nil {
			return errs.NewInvalidInputError(op, core.SessionTokenAudienceKey, "audience must be a string", nil)
		}
		issued, err := tokens.Issue(rctx.Ctx, core.SessionTokenRequest{Audience: audience})
		if err != nil {
			return err
		}
		// The body is a credential.
		rctx.Response.SetHeader("Cache-Control", "no-store")
		return rctx.Response.JSON(http.StatusOK, behemoth.M{
			"token":                      issued.Token,
			"expires_at":                 issued.ExpiresAt.UTC().Format(time.RFC3339),
			core.SessionTokenAudienceKey: issued.Audience,
		})
	}
}
