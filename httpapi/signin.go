package httpapi

import (
	"maps"
	"net/http"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/models"
)

// Keys of the JSON body WriteSignIn answers with.
const (
	SignInUserKey   = "user"   // the signed-in user
	SignInTokenKey  = "token"  // the session token, under DeliveryBody only
	SignInStatusKey = "status" // SignInStatusSecondFactor, when one is pending
)

// SignInStatusSecondFactor is the status of a sign-in whose session waits
// for a second factor. The response then has no user.
const SignInStatusSecondFactor = "requires_second_factor"

// WriteSignIn answers a route with a finished sign-in. Every sign-in route
// calls it, so that a client parses one shape whichever plugin signed the
// user in, and so that the session token reaches the client the way
// RouterConfig.Carrier says:
//
//	{"user": {...}}                                  the session is active; the user's public columns
//	{"status": "requires_second_factor"}             a second factor is pending
//	{"user": {...}, "token": "..."}                  the same, under DeliveryBody
//	{"status": "requires_second_factor", "token": "..."}
//
// It hands the token to the token carrier first (TokenCarrier.Write: the
// cookie, the response header), and adds it to the body when the carrier
// says the body is where it goes. A pending session's token is delivered
// like an active one's: the client needs it to present the second factor.
//
// extra is added to the body, for what a plugin returns next to the user,
// such as the magic link plugin's redirect URL. It can't replace the keys
// above. The response is marked Cache-Control: no-store: it carries a
// credential in every delivery.
func WriteSignIn(rctx *RequestContext, result *core.SignInResult, extra behemoth.M) error {
	body := behemoth.M{}
	maps.Copy(body, extra)
	delete(body, SignInUserKey)
	delete(body, SignInTokenKey)
	delete(body, SignInStatusKey)

	if result.Session.State == models.SessionPending {
		body[SignInStatusKey] = SignInStatusSecondFactor
	} else {
		// The user's public columns, not the model: see schema.PublicView.
		user, err := rctx.Auth.Public.Of(result.User)
		if err != nil {
			return err
		}
		body[SignInUserKey] = user
	}
	if rctx.TokenCarrier.Write(rctx, result.RawToken, result.Session.ExpiresAt) {
		body[SignInTokenKey] = result.RawToken
	}
	rctx.Response.SetHeader("Cache-Control", "no-store")
	return rctx.Response.JSON(http.StatusOK, body)
}
