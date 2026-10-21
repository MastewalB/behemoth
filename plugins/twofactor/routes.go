package twofactor

import (
	"encoding/json"
	"net/http"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/httpapi"
	"github.com/MastewalB/behemoth/plugins/phonenumber"
)

// Paths of the plugin's routes, below the router's base path.
const (
	PathStatus        = "/two-factor"
	PathEnroll        = "/two-factor/enroll"
	PathConfirm       = "/two-factor/confirm"
	PathDisable       = "/two-factor/disable"
	PathRecoveryCodes = "/two-factor/recovery-codes"
	PathChallenge     = "/two-factor/challenge"
	PathSendOTP       = "/two-factor/send-otp"
	PathVerify        = "/two-factor/verify"
)

// Keys of the request and response bodies, besides the hook payload keys.
const (
	keyCode          = "code"
	keyMetadata      = "metadata"
	keyStatus        = "status"
	keyMethods       = "methods"
	keyLocked        = "locked"
	keyRecoveryCodes = "recovery_codes"
)

// Routes implements [httpapi.Plugin]. The setup routes act on the caller's
// own account, and the challenge routes on the caller's pending sign-in;
// each flow reads the caller itself, so no route has a session middleware.
func (p *Plugin) Routes() []httpapi.Route {
	return []httpapi.Route{
		{Method: http.MethodGet, Path: PathStatus, Handler: p.handleStatus},
		{Method: http.MethodPost, Path: PathEnroll, Handler: p.handleEnroll},
		{Method: http.MethodPost, Path: PathConfirm, Handler: p.handleConfirm},
		{Method: http.MethodPost, Path: PathDisable, Handler: p.handleDisable},
		{Method: http.MethodPost, Path: PathRecoveryCodes, Handler: p.handleRecoveryCodes},
		{Method: http.MethodGet, Path: PathChallenge, Handler: p.handleChallenge},
		{Method: http.MethodPost, Path: PathSendOTP, Handler: p.handleSendOTP},
		{Method: http.MethodPost, Path: PathVerify, Handler: p.handleVerify},
	}
}

// Middlewares implements [httpapi.Plugin]. The plugin has no middleware.
func (p *Plugin) Middlewares() []httpapi.Middleware {
	return nil
}

// FromMap sets the request from a request body: "method", "phone_number",
// and "metadata". A missing value is left empty, for Enroll to refuse; one
// of the wrong type is a validation error.
func (r *EnrollRequest) FromMap(data map[string]any) error {
	const op = "twofactor.Enroll"
	method, err := stringField(op, data, keyMethod)
	if err != nil {
		return err
	}
	number, err := stringField(op, data, phonenumber.HookValuePhoneNumber)
	if err != nil {
		return err
	}
	metadata, err := metadataField(op, data)
	if err != nil {
		return err
	}
	r.Method, r.PhoneNumber, r.Metadata = Method(method), number, metadata
	return nil
}

// FromMap sets the request from a request body: "method" and "code".
func (r *ConfirmRequest) FromMap(data map[string]any) error {
	method, code, err := methodAndCode("twofactor.Confirm", data)
	r.Method, r.Code = method, code
	return err
}

// FromMap sets the request from a request body: "method".
func (r *DisableRequest) FromMap(data map[string]any) error {
	method, err := stringField("twofactor.Disable", data, keyMethod)
	r.Method = Method(method)
	return err
}

// FromMap sets the request from a request body: "method" and "metadata".
func (r *SendCodeRequest) FromMap(data map[string]any) error {
	const op = "twofactor.SendCode"
	method, err := stringField(op, data, keyMethod)
	if err != nil {
		return err
	}
	metadata, err := metadataField(op, data)
	if err != nil {
		return err
	}
	r.Method, r.Metadata = Method(method), metadata
	return nil
}

// FromMap sets the request from a request body: "method" and "code".
func (r *VerifyRequest) FromMap(data map[string]any) error {
	method, code, err := methodAndCode("twofactor.Verify", data)
	r.Method, r.Code = method, code
	return err
}

func methodAndCode(op string, data map[string]any) (Method, string, error) {
	method, err := stringField(op, data, keyMethod)
	if err != nil {
		return "", "", err
	}
	code, err := stringField(op, data, keyCode)
	if err != nil {
		return "", "", err
	}
	return Method(method), code, nil
}

// stringField reads a string from a request body. A missing or null key is
// empty; a value of another type is a validation error named after the key.
func stringField(op string, data map[string]any, key string) (string, error) {
	switch v := data[key].(type) {
	case nil:
		return "", nil
	case string:
		return v, nil
	default:
		return "", errs.NewInvalidInputError(op, key, key+" must be a string", nil)
	}
}

// metadataField reads the optional "metadata" object of a request body.
func metadataField(op string, data map[string]any) (behemoth.M, error) {
	switch v := data[keyMetadata].(type) {
	case nil:
		return nil, nil
	case map[string]any:
		return v, nil
	default:
		return nil, errs.NewInvalidInputError(op, keyMetadata, keyMetadata+" must be an object", nil)
	}
}

// decode reads the request's JSON body into in. A body that is not a JSON
// object is a validation error.
func decode(rctx *httpapi.RequestContext, op string, in interface{ FromMap(map[string]any) error }) error {
	var data behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&data); err != nil {
		return errs.NewValidationError(op, "request", err)
	}
	return in.FromMap(data)
}

// answer writes body with Cache-Control: no-store. Every answer of the
// plugin is about one account, and some carry a secret, a recovery code, or
// a token.
func answer(rctx *httpapi.RequestContext, body behemoth.M) error {
	rctx.Response.SetHeader("Cache-Control", "no-store")
	return rctx.Response.JSON(http.StatusOK, body)
}

// handleStatus answers with the caller's methods, by name, with the
// destinations in full: the caller is their owner.
func (p *Plugin) handleStatus(rctx *httpapi.RequestContext) error {
	status, err := p.Status(rctx.Ctx)
	if err != nil {
		return err
	}
	methods := make([]behemoth.M, 0, len(status.Methods))
	for _, m := range status.Methods {
		entry := behemoth.M{keyMethod: string(m.Method), "confirmed_at": m.ConfirmedAt}
		if m.Destination != "" {
			entry[keyDestination] = m.Destination
		}
		methods = append(methods, entry)
	}
	return answer(rctx, behemoth.M{keyMethods: methods, "recovery_codes_left": status.RecoveryCodesLeft, keyLocked: status.Locked})
}

// handleEnroll answers a TOTP setup with the secret and the link, and an
// email or SMS setup with the status of the code that was sent.
func (p *Plugin) handleEnroll(rctx *httpapi.RequestContext) error {
	var req EnrollRequest
	if err := decode(rctx, "twofactor.Enroll", &req); err != nil {
		return err
	}
	enrollment, err := p.Enroll(rctx.Ctx, req)
	if err != nil {
		return err
	}
	if enrollment.Method == MethodTOTP {
		return answer(rctx, behemoth.M{"secret": enrollment.Secret, "uri": enrollment.URI})
	}
	return answer(rctx, behemoth.M{keyStatus: "code_sent"})
}

// handleConfirm answers with the recovery codes when the method is the
// caller's first, the only time they are shown.
func (p *Plugin) handleConfirm(rctx *httpapi.RequestContext) error {
	var req ConfirmRequest
	if err := decode(rctx, "twofactor.Confirm", &req); err != nil {
		return err
	}
	result, err := p.Confirm(rctx.Ctx, req)
	if err != nil {
		return err
	}
	body := behemoth.M{keyStatus: "enabled"}
	if len(result.RecoveryCodes) > 0 {
		body[keyRecoveryCodes] = result.RecoveryCodes
	}
	return answer(rctx, body)
}

func (p *Plugin) handleDisable(rctx *httpapi.RequestContext) error {
	var req DisableRequest
	if err := decode(rctx, "twofactor.Disable", &req); err != nil {
		return err
	}
	if _, err := p.Disable(rctx.Ctx, req); err != nil {
		return err
	}
	return answer(rctx, behemoth.M{keyStatus: "disabled"})
}

// handleRecoveryCodes reads no body.
func (p *Plugin) handleRecoveryCodes(rctx *httpapi.RequestContext) error {
	codes, err := p.RegenerateRecoveryCodes(rctx.Ctx)
	if err != nil {
		return err
	}
	return answer(rctx, behemoth.M{keyRecoveryCodes: codes})
}

func (p *Plugin) handleChallenge(rctx *httpapi.RequestContext) error {
	challenge, err := p.Challenge(rctx.Ctx)
	if err != nil {
		return err
	}
	methods := make([]behemoth.M, 0, len(challenge.Methods))
	for _, m := range challenge.Methods {
		entry := behemoth.M{keyMethod: string(m.Method)}
		if m.Destination != "" {
			entry[keyDestination] = m.Destination
		}
		methods = append(methods, entry)
	}
	return answer(rctx, behemoth.M{keyMethods: methods, keyLocked: challenge.Locked})
}

func (p *Plugin) handleSendOTP(rctx *httpapi.RequestContext) error {
	var req SendCodeRequest
	if err := decode(rctx, "twofactor.SendCode", &req); err != nil {
		return err
	}
	if _, err := p.SendCode(rctx.Ctx, req); err != nil {
		return err
	}
	return answer(rctx, behemoth.M{keyStatus: "code_sent"})
}

// handleVerify answers the way every sign-in route does (httpapi.WriteSignIn):
// the user, and the new session token by the configured delivery.
func (p *Plugin) handleVerify(rctx *httpapi.RequestContext) error {
	var req VerifyRequest
	if err := decode(rctx, "twofactor.Verify", &req); err != nil {
		return err
	}
	result, err := p.Verify(rctx.Ctx, req)
	if err != nil {
		return err
	}
	return httpapi.WriteSignIn(rctx, result, nil)
}

var _ httpapi.Plugin = (*Plugin)(nil)
