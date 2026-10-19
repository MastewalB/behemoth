package plugins_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/plugins/oauth"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signInTrace keeps what the handlers on core's sign-in and sign-up points
// were given during a test.
type signInTrace struct {
	signInBefore []behemoth.M
	signInAfter  []*types.SignInResult
	signInFailed []types.FailureReason
	signUpBefore []behemoth.M
	signUpAfter  []*models.User
	signUpFailed []types.FailureReason
	// provider is HookValueProvider as each auth.signIn.after handler saw it.
	provider []any
	// signUpGate, when set, decides for the handler on auth.signUp.before.
	// An owner has one handler per point, and that one is the trace's.
	signUpGate types.BeforeHookFunc
}

// register attaches the trace's handlers, and then more, if any.
func (tr *signInTrace) register(more ...func(reg types.HookRegistry) error) func(reg types.HookRegistry) error {
	return func(reg types.HookRegistry) error {
		before := func(into *[]behemoth.M) types.BeforeHookFunc {
			return func(_ *types.HookContext, payload behemoth.M) (behemoth.M, error) {
				*into = append(*into, payload)
				return nil, nil
			}
		}
		failed := func(into *[]types.FailureReason) types.FailedHookFunc {
			return func(_ *types.HookContext, reason types.FailureReason) error {
				*into = append(*into, reason)
				return nil
			}
		}
		steps := []error{
			reg.OnBefore(hooks.HookSignInBefore, before(&tr.signInBefore), nil),
			reg.OnAfter(hooks.HookSignInAfter, func(hctx *types.HookContext, result any) error {
				tr.signInAfter = append(tr.signInAfter, result.(*types.SignInResult))
				tr.provider = append(tr.provider, hctx.Values[oauth.HookValueProvider])
				return nil
			}, nil),
			reg.OnFailed(hooks.HookSignInFailed, failed(&tr.signInFailed), nil),
			reg.OnBefore(hooks.HookSignUpBefore, func(hctx *types.HookContext, payload behemoth.M) (behemoth.M, error) {
				tr.signUpBefore = append(tr.signUpBefore, payload)
				if tr.signUpGate != nil {
					return tr.signUpGate(hctx, payload)
				}
				return nil, nil
			}, nil),
			reg.OnAfter(hooks.HookSignUpAfter, func(_ *types.HookContext, result any) error {
				tr.signUpAfter = append(tr.signUpAfter, result.(*models.User))
				return nil
			}, nil),
			reg.OnFailed(hooks.HookSignUpFailed, failed(&tr.signUpFailed), nil),
		}
		for _, fn := range more {
			steps = append(steps, fn(reg))
		}
		return errors.Join(steps...)
	}
}

// lastFailure is the code of the last refused sign-in.
func (tr *signInTrace) lastFailure(t *testing.T) string {
	t.Helper()
	require.NotEmpty(t, tr.signInFailed, "auth.signIn.failed did not fire")
	return tr.signInFailed[len(tr.signInFailed)-1].Code
}

// begin starts a sign-in with provider and returns the request that
// completes it: the state the provider was handed, and the binding value.
func (app *oauthApp) begin(t *testing.T, provider *fakeProvider, redirect string) oauth.CompleteRequest {
	t.Helper()
	result, err := app.plugin.Begin(context.Background(), oauth.BeginRequest{Provider: provider.id, RedirectURL: redirect})
	require.NoError(t, err)
	return oauth.CompleteRequest{Provider: provider.id, Code: "code-from-provider", State: provider.last(t).State, Binding: result.Binding}
}

func invalidCallback(err error) bool {
	return hasCode(err, errs.CategoryUnauthorized, oauth.ErrorCodeInvalidCallback)
}

var ada = oauth.Identity{
	Subject: "g-1", Email: " Ada@Example.com ", EmailVerified: true,
	Name: "Ada Lovelace", GivenName: "Ada", FamilyName: "Lovelace", Picture: "https://img.example.com/ada.png",
}

// A subject the provider names for the first time becomes a user and an
// account, and is signed in. The provider gets the verifier of the challenge
// it was sent, and the state works once.
func TestOAuthCompleteSignsUpANewUser(t *testing.T) {
	ctx := context.Background()
	var trace signInTrace
	app, err := bootOAuth(t, oauth.Options{}, trace.register())
	require.NoError(t, err)
	app.google.identity = ada

	req := app.begin(t, app.google, "/dashboard")
	sent := app.google.last(t)
	result, err := app.plugin.Complete(ctx, req)
	require.NoError(t, err)

	// The user is the provider's profile, with a normalized email.
	user := result.User
	assert.Equal(t, "ada@example.com", user.Email)
	assert.True(t, user.EmailVerified, "the provider said it verified the email")
	assert.Equal(t, "Ada", user.Firstname)
	assert.Equal(t, "Lovelace", user.Lastname)
	assert.Equal(t, "https://img.example.com/ada.png", user.ImageUrl)
	assert.Equal(t, "/dashboard", result.RedirectURL)

	// The sign-in is one like any other plugin's.
	assert.Equal(t, oauth.PluginName, result.Method)
	assert.Equal(t, models.SessionActive, result.Session.State)
	assert.Equal(t, user.ID, result.Session.UserID)
	session, err := app.ac.SessionManager.Validate(ctx, result.RawToken)
	require.NoError(t, err)
	assert.Equal(t, result.Session.ID, session.ID)

	// The account is keyed by the provider and the subject, and holds no
	// token of the provider.
	account, err := app.ac.Store.FindAccount(ctx, "google", "g-1")
	require.NoError(t, err)
	assert.Equal(t, user.ID, account.UserID)
	assert.Empty(t, account.AccessToken)
	assert.Empty(t, account.RefreshToken)
	assert.Empty(t, account.IDToken)

	// The provider redeemed the code with what Begin created.
	require.Len(t, app.google.exchanged, 1)
	exchange := app.google.exchanged[0]
	assert.Equal(t, "code-from-provider", exchange.Code)
	assert.Equal(t, sent.RedirectURI, exchange.RedirectURI)
	assert.Equal(t, sent.Nonce, exchange.Nonce)
	assert.Equal(t, sent.CodeChallenge, s256(exchange.CodeVerifier), "the verifier is the one the challenge is of")

	// The points: one sign-in, with a sign-up inside it.
	require.Len(t, trace.signInBefore, 1)
	assert.Equal(t, behemoth.M{"method": "oauth", "provider": "google"}, trace.signInBefore[0],
		"the code, the state and the binding value are not in the payload")
	require.Len(t, trace.signUpBefore, 1)
	assert.Equal(t, behemoth.M{
		"method": "oauth", "provider": "google", "email": "ada@example.com", "email_verified": true,
		"firstname": "Ada", "lastname": "Lovelace", "image_url": "https://img.example.com/ada.png",
	}, trace.signUpBefore[0])
	require.Len(t, trace.signUpAfter, 1)
	assert.Equal(t, user.ID, trace.signUpAfter[0].ID)
	require.Len(t, trace.signInAfter, 1)
	assert.Equal(t, user.ID, trace.signInAfter[0].User.ID)
	assert.Equal(t, []any{"google"}, trace.provider)
	assert.Empty(t, trace.signInFailed)
	assert.Empty(t, trace.signUpFailed)

	// The state is used up.
	_, err = app.plugin.Complete(ctx, req)
	assert.True(t, invalidCallback(err), "got %v", err)
	assert.Equal(t, "invalid_oauth_state", trace.lastFailure(t))
	assert.Equal(t, 1, app.google.exchanges(), "a used state does not reach the provider")
	assert.Equal(t, 1, app.count(t, "users", "1 = 1"))
	assert.Equal(t, 1, app.count(t, "sessions", "1 = 1"))
}

// A subject that has an account signs in its user, whatever email and name
// the provider reports now. The user is found by the subject and nothing
// else.
func TestOAuthCompleteSignsInAKnownAccount(t *testing.T) {
	ctx := context.Background()
	var trace signInTrace
	app, err := bootOAuth(t, oauth.Options{}, trace.register())
	require.NoError(t, err)
	app.google.identity = ada
	first, err := app.plugin.Complete(ctx, app.begin(t, app.google, ""))
	require.NoError(t, err)

	// The same subject, with another email, and then with none.
	for _, identity := range []oauth.Identity{
		{Subject: "g-1", Email: "countess@example.com", GivenName: "Augusta"},
		{Subject: "g-1"},
	} {
		app.google.identity = identity
		again, err := app.plugin.Complete(ctx, app.begin(t, app.google, ""))
		require.NoError(t, err)
		assert.Equal(t, first.User.ID, again.User.ID)
		assert.Equal(t, "ada@example.com", again.User.Email, "the provider's profile does not overwrite the user")
		assert.Equal(t, "Ada", again.User.Firstname)
		assert.NotEqual(t, first.Session.ID, again.Session.ID, "each sign-in has a session of its own")
		assert.Empty(t, again.RedirectURL)
	}

	assert.Equal(t, 1, app.count(t, "users", "1 = 1"))
	assert.Equal(t, 1, app.count(t, "accounts", "1 = 1"))
	assert.Len(t, trace.signUpBefore, 1, "only the first sign-in was a sign-up")
	assert.Len(t, trace.signInAfter, 3)
}

// Everything that is wrong with a callback gets one answer, and the failed
// point says what it was. A check that fails before the state is consumed
// leaves the state usable, and nothing reaches the provider.
func TestOAuthCompleteRefusesABadCallback(t *testing.T) {
	ctx := context.Background()
	var trace signInTrace
	github := &fakeProvider{id: "github", identity: oauth.Identity{Subject: "gh-1", Email: "ada@example.com"}}
	google := &fakeProvider{id: "google", identity: ada}
	app, err := bootOAuth(t, oauth.Options{CustomProviders: []oauth.Provider{google, github}}, trace.register())
	require.NoError(t, err)

	good := app.begin(t, google, "")
	change := func(fn func(*oauth.CompleteRequest)) oauth.CompleteRequest {
		req := good
		fn(&req)
		return req
	}
	otherSignIn := app.begin(t, google, "")
	cases := []struct {
		name string
		req  oauth.CompleteRequest
		code string
	}{
		{"a state that was never issued", change(func(r *oauth.CompleteRequest) { r.State = "never-issued" }), "invalid_oauth_state"},
		{"another binding value", change(func(r *oauth.CompleteRequest) { r.Binding = "guessed" }), "oauth_binding_mismatch"},
		{"the binding value of another sign-in", change(func(r *oauth.CompleteRequest) { r.Binding = otherSignIn.Binding }), "oauth_binding_mismatch"},
		{"no binding value", change(func(r *oauth.CompleteRequest) { r.Binding = "" }), "oauth_binding_mismatch"},
		{"the state as the binding value", change(func(r *oauth.CompleteRequest) { r.Binding = r.State }), "oauth_binding_mismatch"},
		{"a code that arrived at another provider's page", change(func(r *oauth.CompleteRequest) { r.Provider = "github" }), "oauth_provider_mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := app.plugin.Complete(ctx, tc.req)
			assert.True(t, invalidCallback(err), "got %v", err)
			assert.Equal(t, tc.code, trace.lastFailure(t))
			assert.Equal(t, behemoth.M{"provider": tc.req.Provider}, trace.signInFailed[len(trace.signInFailed)-1].Metadata)
		})
	}
	assert.Zero(t, google.exchanges()+github.exchanges(), "none of them reached a provider")
	assert.Zero(t, app.count(t, "users", "1 = 1"))

	// None of them ended the sign-in they were aimed at.
	result, err := app.plugin.Complete(ctx, good)
	require.NoError(t, err, "the state still works for the client that started the sign-in")
	assert.Equal(t, "ada@example.com", result.User.Email)

	t.Run("a state that expired", func(t *testing.T) {
		var trace signInTrace
		app, err := bootOAuth(t, oauth.Options{StateTTL: time.Nanosecond}, trace.register())
		require.NoError(t, err)
		app.google.identity = ada
		req := app.begin(t, app.google, "")
		time.Sleep(time.Millisecond)
		_, err = app.plugin.Complete(ctx, req)
		assert.True(t, invalidCallback(err), "got %v", err)
		assert.Equal(t, "invalid_oauth_state", trace.lastFailure(t))
		assert.Zero(t, app.google.exchanges())
	})
}

// A code the provider refuses is the user's to retry: the one answer, and a
// refused sign-in. A provider that fails is a failure of the system, and no
// refused sign-in. Both have used the state up.
func TestOAuthCompleteWhenTheExchangeFails(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name     string
		break_   func(*fakeProvider)
		refused  bool
		failCode string
	}{
		{"the provider refuses the code", func(f *fakeProvider) {
			f.exchangeErr = fmt.Errorf("invalid_grant: %w", oauth.ErrExchangeRefused)
		}, true, "oauth_exchange_refused"},
		{"the provider can't be reached", func(f *fakeProvider) { f.exchangeErr = errors.New("dial tcp: timeout") }, false, ""},
		{"the provider names no subject", func(f *fakeProvider) { f.identity = oauth.Identity{Email: "ada@example.com"} }, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var trace signInTrace
			app, err := bootOAuth(t, oauth.Options{}, trace.register())
			require.NoError(t, err)
			app.google.identity = ada
			tc.break_(app.google)

			req := app.begin(t, app.google, "")
			_, err = app.plugin.Complete(ctx, req)
			require.Error(t, err)
			if tc.refused {
				assert.True(t, invalidCallback(err), "got %v", err)
				assert.Equal(t, tc.failCode, trace.lastFailure(t))
			} else {
				assert.False(t, errs.IsRejection(err), "it is not the caller's mistake: %v", err)
				assert.Empty(t, trace.signInFailed, "an outage is not a refused sign-in")
			}
			assert.Zero(t, app.count(t, "users", "1 = 1"))
			assert.Zero(t, app.count(t, "sessions", "1 = 1"))

			// The state went with the attempt.
			app.google.exchangeErr, app.google.identity = nil, ada
			_, err = app.plugin.Complete(ctx, req)
			assert.True(t, invalidCallback(err), "got %v", err)
			assert.Equal(t, 1, app.google.exchanges())
		})
	}
}

// A request that lacks a part is a validation error, before anything is
// read or fired.
func TestOAuthCompleteNeedsItsInput(t *testing.T) {
	ctx := context.Background()
	var trace signInTrace
	app, err := bootOAuth(t, oauth.Options{}, trace.register())
	require.NoError(t, err)
	app.google.identity = ada
	good := app.begin(t, app.google, "")

	for key, req := range map[string]oauth.CompleteRequest{
		"provider": {Code: good.Code, State: good.State, Binding: good.Binding},
		"code":     {Provider: "google", State: good.State, Binding: good.Binding},
		"state":    {Provider: "google", Code: good.Code, Binding: good.Binding},
	} {
		_, err := app.plugin.Complete(ctx, req)
		assert.True(t, hasCode(err, errs.CategoryValidation, key+"_invalid_input"), "%s: got %v", key, err)
	}
	assert.Empty(t, trace.signInBefore)
	assert.Empty(t, trace.signInFailed)

	_, err = app.plugin.Complete(ctx, good)
	assert.NoError(t, err, "the state is untouched")

	unbooted := oauth.New(oauth.Options{CustomProviders: []oauth.Provider{&fakeProvider{id: "google"}}, CallbackURL: "https://app.example.com/cb"})
	_, err = unbooted.Complete(ctx, good)
	assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "got %v", err)
}

// An email is not an identity. A new subject whose email belongs to a user
// is refused, verified or not, and the user gets no account and no session.
func TestOAuthCompleteDoesNotLinkByEmail(t *testing.T) {
	ctx := context.Background()
	var trace signInTrace
	app, err := bootOAuth(t, oauth.Options{}, trace.register())
	require.NoError(t, err)
	existing := &models.User{Email: "ada@example.com", EmailVerified: true}
	require.NoError(t, app.ac.Store.CreateUser(ctx, existing))

	for _, verified := range []bool{true, false} {
		identity := ada
		identity.EmailVerified = verified
		app.google.identity = identity

		_, err = app.plugin.Complete(ctx, app.begin(t, app.google, ""))
		assert.True(t, hasCode(err, errs.CategoryConflict, oauth.ErrorCodeAccountNotLinked), "got %v", err)
		reason := trace.signInFailed[len(trace.signInFailed)-1]
		assert.Equal(t, "account_not_linked", reason.Code)
		assert.Equal(t, models.UserTable, reason.SubjectType)
		assert.Equal(t, existing.ID, reason.SubjectID, "the audit event names the account that was aimed at")
	}

	assert.Zero(t, app.count(t, "accounts", "1 = 1"))
	assert.Zero(t, app.count(t, "sessions", "1 = 1"))
	assert.Equal(t, 1, app.count(t, "users", "1 = 1"))
	assert.Empty(t, trace.signUpBefore, "it was not a sign-up")
}

// A first sign-in needs an email from the provider. One that is missing or
// not an address is refused, with a code of its own.
func TestOAuthCompleteNeedsAnEmailForANewUser(t *testing.T) {
	ctx := context.Background()
	var trace signInTrace
	app, err := bootOAuth(t, oauth.Options{}, trace.register())
	require.NoError(t, err)

	for _, email := range []string{"", "   ", "not-an-address", strings.Repeat("a", 250) + "@example.com"} {
		app.google.identity = oauth.Identity{Subject: "g-2", Email: email, GivenName: "Grace"}
		_, err = app.plugin.Complete(ctx, app.begin(t, app.google, ""))
		assert.True(t, hasCode(err, errs.CategoryForbidden, oauth.ErrorCodeEmailNotProvided), "%q: got %v", email, err)
		assert.Equal(t, "email_not_provided", trace.lastFailure(t))
	}
	assert.Zero(t, app.count(t, "users", "1 = 1"))
	assert.Empty(t, trace.signUpBefore)
}

// What the provider says about the user is taken as far as it goes: an
// unverified email stays unverified, a full name stands in for its parts,
// and a picture that is not a web address is dropped.
func TestOAuthCompleteBuildsTheUserFromTheIdentity(t *testing.T) {
	ctx := context.Background()
	app, err := bootOAuth(t, oauth.Options{}, nil)
	require.NoError(t, err)

	app.google.identity = oauth.Identity{
		Subject: "g-3", Email: "grace@example.com", Name: "  Grace Hopper ", Picture: "javascript:alert(1)",
	}
	result, err := app.plugin.Complete(ctx, app.begin(t, app.google, ""))
	require.NoError(t, err)
	assert.False(t, result.User.EmailVerified, "the provider did not say it verified the email")
	assert.Equal(t, "Grace Hopper", result.User.Firstname)
	assert.Empty(t, result.User.Lastname)
	assert.Empty(t, result.User.ImageUrl)

	app.google.identity = oauth.Identity{Subject: "g-4", Email: "long@example.com", GivenName: strings.Repeat("é", 300)}
	result, err = app.plugin.Complete(ctx, app.begin(t, app.google, ""))
	require.NoError(t, err)
	assert.Equal(t, strings.Repeat("é", 255), result.User.Firstname, "a name is cut to the column, at a character")
}

// A handler on auth.signIn.credentialsVerified decides about a second
// factor, as for every other sign-in: it can make the session pending, or
// refuse.
func TestOAuthCompletePassesTheSecondFactorPoint(t *testing.T) {
	ctx := context.Background()
	var trace signInTrace
	answer := "stepUp"
	app, err := bootOAuth(t, oauth.Options{}, trace.register(func(reg types.HookRegistry) error {
		return reg.OnBefore(hooks.HookSignInCredentialsVerified, func(_ *types.HookContext, payload behemoth.M) (behemoth.M, error) {
			if answer == "refuse" {
				return nil, errs.NewUnauthorized("test", "account_suspended", "account suspended")
			}
			payload["requireStepUp"] = true
			return payload, nil
		}, nil)
	}))
	require.NoError(t, err)
	app.google.identity = ada

	result, err := app.plugin.Complete(ctx, app.begin(t, app.google, ""))
	require.NoError(t, err)
	assert.Equal(t, models.SessionPending, result.Session.State, "a second factor is still asked for")
	_, err = app.ac.SessionManager.Validate(ctx, result.RawToken)
	assert.Error(t, err, "a pending session does not authenticate")

	answer = "refuse"
	_, err = app.plugin.Complete(ctx, app.begin(t, app.google, ""))
	assert.True(t, hasCode(err, errs.CategoryUnauthorized, "account_suspended"), "the handler's error is returned: %v", err)
	reason := trace.signInFailed[len(trace.signInFailed)-1]
	assert.Equal(t, types.FailureRejectedByHook, reason.Code)
	assert.Equal(t, result.User.ID, reason.SubjectID)
	assert.Equal(t, 1, app.count(t, "sessions", "1 = 1"), "the refused sign-in has no session")
}

// A handler on auth.signUp.before can keep a new user out. Both the sign-up
// and the sign-in then count as refused, and nothing is written.
func TestOAuthCompleteSignUpCanBeRefused(t *testing.T) {
	ctx := context.Background()
	trace := signInTrace{signUpGate: func(_ *types.HookContext, payload behemoth.M) (behemoth.M, error) {
		if email, _ := payload["email"].(string); !strings.HasSuffix(email, "@example.com") {
			return nil, errs.NewUnauthorized("test", "domain_not_allowed", "sign-up is by invitation")
		}
		return nil, nil
	}}
	app, err := bootOAuth(t, oauth.Options{}, trace.register())
	require.NoError(t, err)

	app.google.identity = oauth.Identity{Subject: "g-9", Email: "mallory@elsewhere.test", EmailVerified: true}
	_, err = app.plugin.Complete(ctx, app.begin(t, app.google, ""))
	assert.True(t, hasCode(err, errs.CategoryUnauthorized, "domain_not_allowed"), "the handler's error is returned: %v", err)
	require.Len(t, trace.signUpFailed, 1)
	assert.Equal(t, types.FailureRejectedByHook, trace.signUpFailed[0].Code)
	assert.Equal(t, types.FailureRejectedByHook, trace.lastFailure(t))
	assert.Zero(t, app.count(t, "users", "1 = 1"))
	assert.Zero(t, app.count(t, "accounts", "1 = 1"))
	assert.Empty(t, trace.signUpAfter)

	app.google.identity = ada
	_, err = app.plugin.Complete(ctx, app.begin(t, app.google, ""))
	assert.NoError(t, err, "an allowed address signs up")
}

// Two callbacks of one new person can both find no account. The one that
// loses the insert looks again and signs in the user the other created.
// When the winner was a sign-up with the same email by another way, the
// loser is refused like any email that is taken.
func TestOAuthCompleteLosesARaceForANewUser(t *testing.T) {
	ctx := context.Background()
	for name, withAccount := range map[string]bool{
		"to a callback of the same person":       true,
		"to another sign-up with the same email": false,
	} {
		t.Run(name, func(t *testing.T) {
			var winner *models.User
			// The other request commits between this one's lookups and its
			// insert.
			trace := signInTrace{signUpGate: func(hctx *types.HookContext, _ behemoth.M) (behemoth.M, error) {
				if winner != nil {
					return nil, nil
				}
				winner = &models.User{Email: "ada@example.com"}
				if err := hctx.Auth.Store.CreateUser(hctx.Ctx, winner); err != nil {
					return nil, err
				}
				if !withAccount {
					return nil, nil
				}
				return nil, hctx.Auth.Store.CreateAccount(hctx.Ctx, &models.Account{UserID: winner.ID, ProviderID: "google", AccountID: "g-1"})
			}}
			app, err := bootOAuth(t, oauth.Options{}, trace.register())
			require.NoError(t, err)
			app.google.identity = ada

			result, err := app.plugin.Complete(ctx, app.begin(t, app.google, ""))
			if withAccount {
				require.NoError(t, err)
				assert.Equal(t, winner.ID, result.User.ID)
				assert.Equal(t, 1, app.count(t, "sessions", "1 = 1"))
			} else {
				assert.True(t, hasCode(err, errs.CategoryConflict, oauth.ErrorCodeAccountNotLinked), "got %v", err)
				assert.Zero(t, app.count(t, "sessions", "1 = 1"))
			}
			assert.Equal(t, 1, app.count(t, "users", "1 = 1"))
			assert.Empty(t, trace.signUpAfter, "the plugin created no user")
		})
	}
}
