package plugins_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MastewalB/behemoth/engine"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/httpapi"
	"github.com/MastewalB/behemoth/plugins/twofactor"
	"github.com/MastewalB/behemoth/plugins/twofactor/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// twoFactorBody holds the keys the plugin's routes answer with.
type twoFactorBody struct {
	Status            string           `json:"status"`
	Code              string           `json:"code"`
	Secret            string           `json:"secret"`
	URI               string           `json:"uri"`
	RecoveryCodes     []string         `json:"recovery_codes"`
	RecoveryCodesLeft int              `json:"recovery_codes_left"`
	Locked            bool             `json:"locked"`
	Methods           []map[string]any `json:"methods"`
	User              map[string]any   `json:"user"`
}

// The routes set a method up and finish a sign-in, with the bodies and
// statuses a client depends on. Each answer is marked no-store.
func TestTwoFactorRoutes(t *testing.T) {
	routes := mountedRoutes{}
	app := bootTwoFactor(t, twofactor.Options{Issuer: "Example", Methods: []twofactor.Method{twofactor.MethodTOTP, twofactor.MethodEmail}, WaitForSend: true}, func(cfg *engine.BootConfig) {
		cfg.HTTP = routes
		cfg.Router = httpapi.RouterConfig{Carrier: httpapi.TokenCarrierConfig{Delivery: httpapi.DeliveryHeader}}
	})
	route := func(path string) httpapi.Route {
		r, ok := routes["/api/auth"+path]
		require.True(t, ok, path)
		return r
	}
	read := func(w *httptest.ResponseRecorder) twoFactorBody {
		t.Helper()
		var b twoFactorBody
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &b), w.Body.String())
		return b
	}
	_, _, session := app.signedIn(t, "ada@example.com")

	w := callAs(t, app.ac, route(twofactor.PathEnroll), `{"method":"totp"}`, session)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	enrolled := read(w)
	assert.True(t, strings.HasPrefix(enrolled.URI, "otpauth://totp/Example:"), enrolled.URI)
	secret, err := totp.DecodeSecret(enrolled.Secret)
	require.NoError(t, err)

	w = callAs(t, app.ac, route(twofactor.PathConfirm), `{"method":"totp","code":"`+totp.Code(secret, time.Now())+`"}`, session)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	confirmed := read(w)
	assert.Equal(t, "enabled", confirmed.Status)
	assert.Len(t, confirmed.RecoveryCodes, twofactor.DefaultRecoveryCodes)

	w = callAs(t, app.ac, route(twofactor.PathStatus), "", session)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	status := read(w)
	require.Len(t, status.Methods, 1)
	assert.Equal(t, "totp", status.Methods[0]["method"])
	assert.NotEmpty(t, status.Methods[0]["confirmed_at"])
	assert.Equal(t, twofactor.DefaultRecoveryCodes, status.RecoveryCodesLeft)
	assert.False(t, status.Locked)

	w = callAs(t, app.ac, route(twofactor.PathRecoveryCodes), "", session)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Len(t, read(w).RecoveryCodes, twofactor.DefaultRecoveryCodes)

	for input, want := range map[string]struct {
		status int
		code   string
	}{
		`not json`:          {http.StatusBadRequest, "request_validation_error"},
		`{"method":7}`:      {http.StatusBadRequest, "method_invalid_input"},
		`{"method":"fax"}`:  {http.StatusBadRequest, "method_invalid_input"},
		`{"method":"sms"}`:  {http.StatusForbidden, twofactor.ErrorCodeMethodUnavailable},
		`{"method":"totp"}`: {http.StatusOK, ""},
	} {
		w := callAs(t, app.ac, route(twofactor.PathEnroll), input, session)
		assert.Equal(t, want.status, w.Code, "%s: %s", input, w.Body.String())
		if want.code != "" {
			assert.Equal(t, want.code, read(w).Code, input)
		}
	}

	// A sign-in answers with the status, and the plugin's routes finish it.
	w = call(t, app.ac, route("/sign-in/email"), `{"email":"ada@example.com","password":"correct horse"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, httpapi.SignInStatusSecondFactor, read(w).Status)
	pendingToken := w.Header().Get(httpapi.SessionTokenHeader)
	require.NotEmpty(t, pendingToken)

	w = callAs(t, app.ac, route(twofactor.PathEnroll), `{"method":"totp"}`, pendingToken)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, errs.CodeSessionPending, read(w).Code, "the setup routes refuse a pending session")

	w = callAs(t, app.ac, route(twofactor.PathChallenge), "", pendingToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, []map[string]any{{"method": "totp"}, {"method": "recovery_code"}}, read(w).Methods)

	w = callAs(t, app.ac, route(twofactor.PathVerify), `{"method":"totp","code":"`+wrongTOTP(secret)+`"}`, pendingToken)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, twofactor.ErrorCodeInvalidCode, read(w).Code)

	w = callAs(t, app.ac, route(twofactor.PathVerify), `{"method":"totp","code":"`+nextTOTP(secret)+`"}`, pendingToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "ada@example.com", read(w).User["email"], "the body of a finished sign-in")
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	active := w.Header().Get(httpapi.SessionTokenHeader)
	require.NotEmpty(t, active)
	assert.NotEqual(t, pendingToken, active, "a new token")

	w = callAs(t, app.ac, route(twofactor.PathChallenge), "", pendingToken)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, errs.CodeSessionInvalid, read(w).Code, "the pending token stopped working")
	w = callAs(t, app.ac, route(twofactor.PathChallenge), "", active)
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Equal(t, twofactor.ErrorCodeNotPending, read(w).Code)
	w = callAs(t, app.ac, route(twofactor.PathSendOTP), `{"method":"email"}`, "")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, errs.CodeSessionMissing, read(w).Code)

	w = callAs(t, app.ac, route(twofactor.PathDisable), `{"method":"totp"}`, active)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "disabled", read(w).Status, "the session that passed the second factor is fresh")
}

// The email method's routes send a setup code and a sign-in code, and
// answer without the code.
func TestTwoFactorEmailRoutes(t *testing.T) {
	routes := mountedRoutes{}
	app := bootTwoFactor(t, twofactor.Options{Methods: []twofactor.Method{twofactor.MethodEmail}, WaitForSend: true}, func(cfg *engine.BootConfig) {
		cfg.HTTP = routes
		cfg.Router = httpapi.RouterConfig{Carrier: httpapi.TokenCarrierConfig{Delivery: httpapi.DeliveryHeader}}
	})
	route := func(path string) httpapi.Route { return routes["/api/auth"+path] }
	_, _, session := app.signedIn(t, "ada@example.com")

	w := callAs(t, app.ac, route(twofactor.PathEnroll), `{"method":"email","metadata":{"locale":"am"}}`, session)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `{"status":"code_sent"}`, w.Body.String())
	setup := app.mail.last(t)
	assert.Equal(t, "am", setup.Metadata["locale"])
	w = callAs(t, app.ac, route(twofactor.PathConfirm), `{"method":"email","code":"`+setup.Code+`"}`, session)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = call(t, app.ac, route("/sign-in/email"), `{"email":"ada@example.com","password":"correct horse"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	pendingToken := w.Header().Get(httpapi.SessionTokenHeader)
	w = callAs(t, app.ac, route(twofactor.PathChallenge), "", pendingToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `{"methods":[{"method":"email","destination":"a***@example.com"},{"method":"recovery_code"}],"locked":false}`, w.Body.String())

	w = callAs(t, app.ac, route(twofactor.PathSendOTP), `{"method":"email"}`, pendingToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `{"status":"code_sent"}`, w.Body.String())
	code := app.mail.last(t).Code
	w = callAs(t, app.ac, route(twofactor.PathVerify), `{"method":"email","code":"`+code+`"}`, pendingToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.NotEmpty(t, w.Header().Get(httpapi.SessionTokenHeader))
}
