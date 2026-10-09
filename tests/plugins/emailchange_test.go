package plugins_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/crypto"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/plugins/emailverification"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/types"
	bmth "github.com/MastewalB/behemoth/types/init"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// changeOptions turns the email change flow on.
func changeOptions() emailverification.Options {
	return emailverification.Options{
		ChangeLinkURL: "https://app.example.com/auth/change-email",
		RevertLinkURL: "https://app.example.com/auth/undo-email-change",
	}
}

// verifiedUser creates a user whose email is verified, so nothing is sent
// for it, and a session for that user.
func (app *verificationApp) verifiedUser(t *testing.T, email string) (user *models.User, rawSession string) {
	t.Helper()
	ctx := context.Background()
	user = &models.User{Email: email, EmailVerified: true}
	require.NoError(t, app.ac.Store.CreateUser(ctx, user))
	_, rawSession, err := app.ac.SessionManager.Create(ctx, user.ID, types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	return user, rawSession
}

// mails waits until n messages have been sent in all and returns them. A
// change request's notice is sent before the request returns and its
// confirmation in the background, so the notice comes first.
func (app *verificationApp) mails(t *testing.T, n int) []types.MailMessage {
	t.Helper()
	require.Eventually(t, func() bool { return app.outbox.count() >= n }, 5*time.Second, time.Millisecond, "message %d was not sent", n)
	app.outbox.mu.Lock()
	defer app.outbox.mu.Unlock()
	require.Len(t, app.outbox.links, n)
	return slices.Clone(app.outbox.links)
}

// requestChange asks for a change and returns the notice and the
// confirmation it sent, which are messages n-1 and n.
func (app *verificationApp) requestChange(t *testing.T, userID, newEmail string, n int) (notice, confirm types.MailMessage) {
	t.Helper()
	_, err := app.plugin.RequestChange(context.Background(), emailverification.ChangeRequest{UserID: userID, NewEmail: newEmail})
	require.NoError(t, err)
	msgs := app.mails(t, n)
	return msgs[n-2], msgs[n-1]
}

func (app *verificationApp) emailOf(t *testing.T, userID string) string {
	t.Helper()
	user, err := app.ac.Store.FindUserByID(context.Background(), userID)
	require.NoError(t, err)
	return user.Email
}

func (app *verificationApp) sessionWorks(rawSession string) bool {
	_, err := app.ac.SessionManager.Validate(context.Background(), rawSession)
	return err == nil
}

func changeError(err error, category behemotherr.Category, code string) bool {
	de, ok := errors.AsType[*behemotherr.DomainError](err)
	return ok && de.Category == category && de.Code == code
}

func invalidChangeLink(err error) bool {
	return changeError(err, behemotherr.CategoryUnauthorized, emailverification.ErrorCodeInvalidChangeLink)
}

func emailTaken(err error) bool {
	return changeError(err, behemotherr.CategoryConflict, emailverification.ErrorCodeEmailTaken)
}

// A change request leaves the address alone and sends two messages. The
// link at the new address applies the change, and the link at the old one
// undoes it afterwards and ends the user's sessions.
func TestEmailChangeConfirmAndRevert(t *testing.T) {
	ctx := context.Background()
	app := bootVerification(t, changeOptions())
	user, rawSession := app.verifiedUser(t, "ada@example.com")

	result, err := app.plugin.RequestChange(ctx, emailverification.ChangeRequest{
		UserID: user.ID, NewEmail: " Ada@New.example.com ", RedirectURL: "/settings", Metadata: behemoth.M{"locale": "fr"},
	})
	require.NoError(t, err)
	assert.Equal(t, "ada@example.com", result.OldEmail)
	assert.Equal(t, "ada@new.example.com", result.NewEmail)

	msgs := app.mails(t, 2)
	notice, confirm := msgs[0], msgs[1]
	addresses := behemoth.M{emailverification.DataOldEmail: "ada@example.com", emailverification.DataNewEmail: "ada@new.example.com"}

	assert.Equal(t, types.MailEmailChangeNotice, notice.Kind)
	assert.Equal(t, "ada@example.com", notice.To, "the notice goes to the address the account has")
	assert.True(t, strings.HasPrefix(notice.URL, "https://app.example.com/auth/undo-email-change?token="), notice.URL)
	assert.Equal(t, addresses, notice.Data)
	assert.Equal(t, behemoth.M{"locale": "fr"}, notice.Metadata)
	assert.WithinDuration(t, time.Now().Add(emailverification.DefaultRevertTTL), notice.ExpiresAt, time.Minute)

	assert.Equal(t, types.MailEmailChange, confirm.Kind)
	assert.Equal(t, "ada@new.example.com", confirm.To, "the confirmation goes to the address asked for")
	assert.True(t, strings.HasPrefix(confirm.URL, "https://app.example.com/auth/change-email?token="), confirm.URL)
	assert.Equal(t, addresses, confirm.Data)
	assert.WithinDuration(t, time.Now().Add(emailverification.DefaultChangeTTL), confirm.ExpiresAt, time.Minute)
	assert.Equal(t, confirm.ExpiresAt, result.ExpiresAt)

	assert.Equal(t, "ada@example.com", app.emailOf(t, user.ID), "nothing changes until the new address confirms")

	changed, err := app.plugin.ConfirmChange(ctx, confirm.Token)
	require.NoError(t, err)
	assert.Equal(t, "ada@new.example.com", changed.User.Email)
	assert.True(t, changed.User.EmailVerified, "the link showed who controls the new address")
	assert.Equal(t, "/settings", changed.RedirectURL)
	assert.True(t, app.sessionWorks(rawSession), "a confirmed change leaves the sessions alone")
	_, err = app.plugin.ConfirmChange(ctx, confirm.Token)
	assert.True(t, invalidChangeLink(err), "a confirmation works once: %v", err)

	reverted, err := app.plugin.RevertChange(ctx, notice.Token)
	require.NoError(t, err)
	assert.Equal(t, "ada@example.com", reverted.Email)
	assert.True(t, reverted.EmailVerified)
	assert.Equal(t, "ada@example.com", app.emailOf(t, user.ID))
	assert.False(t, app.sessionWorks(rawSession), "undoing a change ends every session")
	_, err = app.plugin.RevertChange(ctx, notice.Token)
	assert.True(t, invalidChangeLink(err), "a revert works once: %v", err)

	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 2, app.outbox.count(), "neither write sent a verification link: both addresses were confirmed by a link")

	for _, point := range []types.HookPoint{
		emailverification.HookChangeRequestAfter, emailverification.HookChangeConfirmAfter, emailverification.HookChangeRevertAfter,
	} {
		events := app.rec.Audit.OfType(string(point))
		require.Len(t, events, 1, point)
		assert.Equal(t, user.ID, events[0].SubjectID, point)
	}
	refused := app.rec.Audit.OfType(string(emailverification.HookChangeRevertFailed))
	require.Len(t, refused, 1)
	assert.Equal(t, "invalidLink", refused[0].Metadata["code"])
}

// Before the new address confirms, the notice's link drops the pending
// change. A new request replaces the pending one, and a revert ends the
// revert links issued after it.
func TestEmailChangeRevertBeforeConfirm(t *testing.T) {
	ctx := context.Background()
	app := bootVerification(t, changeOptions())
	user, rawSession := app.verifiedUser(t, "ada@example.com")

	firstNotice, firstConfirm := app.requestChange(t, user.ID, "ada@one.example.com", 2)
	secondNotice, secondConfirm := app.requestChange(t, user.ID, "ada@two.example.com", 4)
	_, err := app.plugin.ConfirmChange(ctx, firstConfirm.Token)
	assert.True(t, invalidChangeLink(err), "the second request replaced the first: %v", err)

	kept, err := app.plugin.RevertChange(ctx, firstNotice.Token)
	require.NoError(t, err)
	assert.Equal(t, "ada@example.com", kept.Email, "there was nothing to put back")
	assert.False(t, app.sessionWorks(rawSession), "the sessions end all the same")

	_, err = app.plugin.ConfirmChange(ctx, secondConfirm.Token)
	assert.True(t, invalidChangeLink(err), "the pending change was dropped: %v", err)
	_, err = app.plugin.RevertChange(ctx, secondNotice.Token)
	assert.True(t, invalidChangeLink(err), "a revert link issued after the one that was used: %v", err)
	assert.Equal(t, "ada@example.com", app.emailOf(t, user.ID))
}

// After two changes in a row, the link at the older address wins: it puts
// its address back whatever happened since, and the link at the address in
// between can't undo that. Used first, the newer link does not end the
// older one.
func TestEmailChangeOlderRevertLinkWins(t *testing.T) {
	ctx := context.Background()
	// The account goes from A to B to C. The first return value is the
	// link sent to A, the second the one sent to B.
	changedTwice := func(t *testing.T) (app *verificationApp, userID, linkAtA, linkAtB string) {
		app = bootVerification(t, changeOptions())
		user, _ := app.verifiedUser(t, "a@example.com")
		noticeA, confirmB := app.requestChange(t, user.ID, "b@example.com", 2)
		_, err := app.plugin.ConfirmChange(ctx, confirmB.Token)
		require.NoError(t, err)
		noticeB, confirmC := app.requestChange(t, user.ID, "c@example.com", 4)
		assert.Equal(t, "b@example.com", noticeB.To)
		_, err = app.plugin.ConfirmChange(ctx, confirmC.Token)
		require.NoError(t, err)
		require.Equal(t, "c@example.com", app.emailOf(t, user.ID))
		return app, user.ID, noticeA.Token, noticeB.Token
	}

	t.Run("the older link first", func(t *testing.T) {
		app, userID, linkAtA, linkAtB := changedTwice(t)
		restored, err := app.plugin.RevertChange(ctx, linkAtA)
		require.NoError(t, err)
		assert.Equal(t, "a@example.com", restored.Email, "back to the first address, past the one in between")
		_, err = app.plugin.RevertChange(ctx, linkAtB)
		assert.True(t, invalidChangeLink(err), "the link at B can't take the account back: %v", err)
		assert.Equal(t, "a@example.com", app.emailOf(t, userID))
	})

	t.Run("the newer link first", func(t *testing.T) {
		app, userID, linkAtA, linkAtB := changedTwice(t)
		restored, err := app.plugin.RevertChange(ctx, linkAtB)
		require.NoError(t, err)
		assert.Equal(t, "b@example.com", restored.Email)
		restored, err = app.plugin.RevertChange(ctx, linkAtA)
		require.NoError(t, err, "using the link at B did not end the older link at A")
		assert.Equal(t, "a@example.com", restored.Email)
		assert.Equal(t, "a@example.com", app.emailOf(t, userID))
	})
}

// An address that belongs to another account: at the request nothing goes
// to it, at the confirm and at the revert the write is refused.
func TestEmailChangeToAnAddressThatIsTaken(t *testing.T) {
	ctx := context.Background()
	app := bootVerification(t, changeOptions())
	user, _ := app.verifiedUser(t, "ada@example.com")
	app.verifiedUser(t, "grace@example.com")

	_, err := app.plugin.RequestChange(ctx, emailverification.ChangeRequest{UserID: user.ID, NewEmail: "Grace@example.com"})
	assert.ErrorIs(t, err, emailverification.ErrEmailTaken)
	msgs := app.mails(t, 1)
	assert.Equal(t, types.MailEmailChangeNotice, msgs[0].Kind, "the account's own address is still told")
	failed := app.rec.Audit.OfType(string(emailverification.HookChangeRequestFailed))
	require.Len(t, failed, 1)
	assert.Equal(t, "emailTaken", failed[0].Metadata["code"])

	// Free at the request, taken before the confirm.
	_, confirm := app.requestChange(t, user.ID, "ada@new.example.com", 3)
	app.verifiedUser(t, "ada@new.example.com")
	_, err = app.plugin.ConfirmChange(ctx, confirm.Token)
	assert.True(t, emailTaken(err), "%v", err)
	assert.Equal(t, "ada@example.com", app.emailOf(t, user.ID))

	// The old address is taken after a change went through.
	notice, confirm := app.requestChange(t, user.ID, "ada@third.example.com", 5)
	_, err = app.plugin.ConfirmChange(ctx, confirm.Token)
	require.NoError(t, err)
	app.verifiedUser(t, "ada@example.com")
	_, rawSession, err := app.ac.SessionManager.Create(ctx, user.ID, types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	_, err = app.plugin.RevertChange(ctx, notice.Token)
	assert.True(t, emailTaken(err), "%v", err)
	assert.Equal(t, "ada@third.example.com", app.emailOf(t, user.ID), "the old address could not be put back")
	assert.False(t, app.sessionWorks(rawSession), "the sessions end all the same")
}

// A change whose notice can't be handed to the mail sender does not start.
func TestEmailChangeNeedsItsNotice(t *testing.T) {
	ctx := context.Background()
	app := bootVerification(t, changeOptions())
	user, _ := app.verifiedUser(t, "ada@example.com")

	down := errors.New("smtp down")
	app.outbox.mu.Lock()
	app.outbox.err = down
	app.outbox.mu.Unlock()
	_, err := app.plugin.RequestChange(ctx, emailverification.ChangeRequest{UserID: user.ID, NewEmail: "ada@new.example.com"})
	assert.ErrorIs(t, err, down, "the request waits for the notice and reports its failure")
	app.outbox.mu.Lock()
	app.outbox.err = nil
	app.outbox.mu.Unlock()

	time.Sleep(50 * time.Millisecond)
	msgs := app.mails(t, 1)
	assert.Equal(t, types.MailEmailChangeNotice, msgs[0].Kind, "no confirmation was sent to the new address")
	_, err = app.plugin.RevertChange(ctx, msgs[0].Token)
	assert.True(t, invalidChangeLink(err), "the link of the notice that was not sent is revoked: %v", err)
	failed := app.rec.Audit.OfType(string(emailverification.HookChangeRequestFailed))
	require.Len(t, failed, 1)
	assert.Equal(t, "noticeFailed", failed[0].Metadata["code"])
}

// callAs invokes a mounted route the way call does, with a session token.
func callAs(t *testing.T, ac *types.AuthContext, route types.Route, body, rawSession string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, route.Path, strings.NewReader(body))
	if rawSession != "" {
		req.Header.Set("Authorization", "Bearer "+rawSession)
	}
	rctx := &types.RequestContext{Request: req, Response: types.NewResponseRecorder(), Values: behemoth.M{}, Auth: ac}
	rctx.Ctx = types.ContextWithRequest(req.Context(), rctx)
	err := route.Handler(rctx)
	w := httptest.NewRecorder()
	if err != nil {
		status, body := (&behemotherr.DefaultErrorMapper{}).Map(err)
		w.Code = status
		require.NoError(t, json.NewEncoder(w.Body).Encode(body))
		return w
	}
	rctx.Response.Flush(w)
	return w
}

// The request route needs a session that signed in recently, and answers
// the same for an address that is taken. The confirm and revert routes take
// the token from a mailbox and need no session.
func TestEmailChangeRoutes(t *testing.T) {
	ctx := context.Background()
	opts := changeOptions()
	opts.ChangeLimit = types.Limit{Max: 20, Window: time.Minute}
	app := bootVerification(t, opts, func(cfg *bmth.BootConfig) { cfg.Session.FreshAge = 400 * time.Millisecond })
	change := app.mounted["/api/auth"+emailverification.PathChange]
	confirm := app.mounted["/api/auth"+emailverification.PathChangeConfirm]
	revert := app.mounted["/api/auth"+emailverification.PathChangeRevert]
	require.NotNil(t, change.Handler)
	require.NotNil(t, confirm.Handler)
	require.NotNil(t, revert.Handler)

	user, rawSession := app.verifiedUser(t, "ada@example.com")
	app.verifiedUser(t, "grace@example.com")

	assert.Equal(t, http.StatusUnauthorized, callAs(t, app.ac, change, `{"email":"ada@new.example.com"}`, "").Code, "without a session")

	sent := callAs(t, app.ac, change, `{"email":"ada@new.example.com","redirectURL":"/settings"}`, rawSession)
	require.Equal(t, http.StatusOK, sent.Code, sent.Body.String())
	msgs := app.mails(t, 2)
	notice, link := msgs[0], msgs[1]
	assert.Equal(t, user.ID, link.User.ID, "the user is the session's")

	taken := callAs(t, app.ac, change, `{"email":"grace@example.com"}`, rawSession)
	assert.Equal(t, sent.Code, taken.Code)
	assert.Equal(t, sent.Body.String(), taken.Body.String(), "the response does not tell that the address has an account")

	for body, reason := range map[string]string{
		`{"email":"not an email"}`:    "not an address",
		`{"email":"ADA@example.com"}`: "the address the account has",
		`{"email":"ada@other.example.com","redirectURL":"https://evil.example.com/"}`: "a redirect outside the trusted origins",
	} {
		assert.Equal(t, http.StatusBadRequest, callAs(t, app.ac, change, body, rawSession).Code, reason)
	}

	// The session is valid for an hour, and fresh for 400ms.
	time.Sleep(600 * time.Millisecond)
	require.True(t, app.sessionWorks(rawSession))
	stale := callAs(t, app.ac, change, `{"email":"ada@late.example.com"}`, rawSession)
	assert.Equal(t, http.StatusUnauthorized, stale.Code)
	assert.Contains(t, stale.Body.String(), behemotherr.ErrorCodeSessionNotFresh)
	_, signedInAgain, err := app.ac.SessionManager.Create(ctx, user.ID, types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, callAs(t, app.ac, change, `{"email":"ada@late.example.com"}`, signedInAgain).Code, "signing in again makes a fresh session")
	msgs = app.mails(t, 5) // the taken address got a notice and no confirmation
	latest := msgs[4]
	assert.Equal(t, "ada@late.example.com", latest.To)

	assert.Equal(t, http.StatusBadRequest, call(t, app.ac, confirm, `{}`).Code, "a confirm without a token")
	w := call(t, app.ac, confirm, `{"token":"`+link.Token+`"}`)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "the later request replaced this link")
	assert.Contains(t, w.Body.String(), emailverification.ErrorCodeInvalidChangeLink)

	w = call(t, app.ac, confirm, `{"token":"`+latest.Token+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var body struct {
		User models.User `json:"user"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "ada@late.example.com", body.User.Email)

	w = call(t, app.ac, revert, `{"token":"`+notice.Token+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `{"status":"reverted"}`, w.Body.String())
	assert.Equal(t, "ada@example.com", app.emailOf(t, user.ID))
	assert.False(t, app.sessionWorks(signedInAgain))
	assert.Equal(t, http.StatusUnauthorized, call(t, app.ac, revert, `{"token":"`+notice.Token+`"}`).Code)
}

// Change requests are limited per user, from any caller.
func TestEmailChangeRequestsAreLimitedPerUser(t *testing.T) {
	ctx := context.Background()
	opts := changeOptions()
	opts.ChangeLimit = types.Limit{Max: 2, Window: time.Minute}
	app := bootVerification(t, opts)
	user, _ := app.verifiedUser(t, "ada@example.com")
	other, _ := app.verifiedUser(t, "grace@example.com")

	app.requestChange(t, user.ID, "ada@one.example.com", 2)
	app.requestChange(t, user.ID, "ada@two.example.com", 4)
	_, err := app.plugin.RequestChange(ctx, emailverification.ChangeRequest{UserID: user.ID, NewEmail: "ada@three.example.com"})
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryRateLimited), "the third request of the user: %v", err)
	app.requestChange(t, other.ID, "grace@new.example.com", 6)

	events := app.rec.Audit.OfType(telemetry.AuditRateLimitExceeded)
	require.Len(t, events, 1)
	assert.Equal(t, emailverification.RuleChangeUser, events[0].Metadata["rule"])
}

// The flow is off unless both of its pages are set, and one without the
// other stops Boot.
func TestEmailChangeIsOptIn(t *testing.T) {
	ctx := context.Background()
	app := bootVerification(t, emailverification.Options{})
	user, _ := app.verifiedUser(t, "ada@example.com")
	_, err := app.plugin.RequestChange(ctx, emailverification.ChangeRequest{UserID: user.ID, NewEmail: "ada@new.example.com"})
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%v", err)
	_, err = app.plugin.ConfirmChange(ctx, "token")
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%v", err)
	_, err = app.plugin.RevertChange(ctx, "token")
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%v", err)
	assert.Nil(t, app.mounted["/api/auth"+emailverification.PathChange].Handler, "its routes are not mounted")

	for name, opts := range map[string]emailverification.Options{
		"no revert page":           {ChangeLinkURL: "https://app.example.com/change"},
		"no change page":           {RevertLinkURL: "https://app.example.com/undo"},
		"a relative change page":   {ChangeLinkURL: "/change", RevertLinkURL: "https://app.example.com/undo"},
		"a negative revert window": {ChangeLinkURL: "https://app.example.com/change", RevertLinkURL: "https://app.example.com/undo", RevertTTL: -time.Hour},
	} {
		opts.LinkURL = "https://app.example.com/verify"
		prepared, err := bmth.Prepare([]types.Plugin{emailverification.New(opts)}, bmth.PrepareConfig{})
		require.NoError(t, err, name)
		_, err = bmth.Boot(ctx, prepared, app.ac.DB, bmth.BootConfig{
			Crypto: crypto.Config{
				Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ef", 32)}, Current: 1},
			},
			Mail: types.MailConfig{Sender: app.outbox},
		})
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "emailverification", name)
	}
}
