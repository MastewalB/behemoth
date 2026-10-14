package plugins_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/crypto"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/plugins/emailpassword"
	"github.com/MastewalB/behemoth/plugins/phonenumber"
	sqliteAdapter "github.com/MastewalB/behemoth/storage/adapters/sqlite"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
	bmth "github.com/MastewalB/behemoth/types/init"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// phoneSchema is the schema with the plugin's column.
const phoneSchema = magicLinkSchema + `
ALTER TABLE users ADD COLUMN phone_number TEXT;
CREATE UNIQUE INDEX users_phone_number_key ON users (phone_number);`

// texts is an SMSSender that keeps what it was asked to send, and fails
// when told to.
type texts struct {
	mu   sync.Mutex
	sent []types.SMSMessage
	fail error
}

func (s *texts) Send(_ context.Context, msg types.SMSMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	s.sent = append(s.sent, msg)
	return nil
}

func (s *texts) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
}

// last returns the newest message, which has to be the n-th.
func (s *texts) last(t *testing.T, n int) types.SMSMessage {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.Len(t, s.sent, n)
	return s.sent[n-1]
}

type phoneApp struct {
	ac        *types.AuthContext
	passwords *emailpassword.Plugin
	phones    *phonenumber.Plugin
	routes    mountedRoutes
	sms       *texts
	db        *sql.DB
}

const (
	adaNumber   = "+14155550101"
	graceNumber = "+14155550102"
	password    = "correct horse"
)

// bootPhones boots the email/password and phone number plugins. The sender
// is waited for unless opts say otherwise, so a test reads the code right
// after the call.
func bootPhones(t *testing.T, opts phonenumber.Options, hookFn func(reg types.HookRegistry) error) *phoneApp {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "phone.db")+"?_busy_timeout=10000&_txlock=immediate")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(phoneSchema)
	require.NoError(t, err)

	app := &phoneApp{routes: mountedRoutes{}, sms: &texts{}, db: db}
	app.passwords = emailpassword.New(emailpassword.Options{})
	app.phones = phonenumber.New(app.passwords, opts)
	prepared, err := bmth.Prepare([]types.Plugin{app.passwords, app.phones}, bmth.PrepareConfig{})
	require.NoError(t, err)
	app.ac, err = bmth.Boot(context.Background(), prepared, sqliteAdapter.NewSQLiteAdapter(db, prepared.Resolver), bmth.BootConfig{
		Crypto: crypto.Config{
			Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ef", 32)}, Current: 1},
		},
		Session: types.SessionConfig{Transport: types.TransportHeader},
		SMS:     types.SMSConfig{Sender: app.sms},
		HTTP:    app.routes,
		Hooks:   hookFn,
	})
	require.NoError(t, err)
	t.Cleanup(func() { app.ac.SMS.Close(context.Background()) })
	return app
}

func waited(opts phonenumber.Options) phonenumber.Options {
	opts.WaitForSend = true
	return opts
}

func (app *phoneApp) signUp(t *testing.T, email string) *models.User {
	t.Helper()
	user, err := app.passwords.SignUp(context.Background(), behemoth.M{"email": email, "password": password})
	require.NoError(t, err)
	return user
}

// withNumber signs a user up and gives them number through the code flow.
func (app *phoneApp) withNumber(t *testing.T, email, number string) *models.User {
	t.Helper()
	ctx := context.Background()
	user := app.signUp(t, email)
	before := app.sms.count()
	sent, err := app.phones.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: number, UserID: user.ID})
	require.NoError(t, err)
	require.True(t, sent.Sent, sent.Reason)
	user, err = app.phones.AddNumber(ctx, user.ID, number, app.sms.last(t, before+1).Code)
	require.NoError(t, err)
	return user
}

func (app *phoneApp) numberOf(t *testing.T, userID string) (string, bool) {
	t.Helper()
	user, err := app.ac.Store.FindUserByID(context.Background(), userID)
	require.NoError(t, err)
	number, ok, err := phonenumber.Column.Get(user)
	require.NoError(t, err)
	return number, ok
}

func invalidPhoneCode(err error) bool {
	return hasCode(err, behemotherr.CategoryUnauthorized, phonenumber.ErrorCodeInvalidCode)
}

// wrongCode returns a code of the same length that is not code.
func wrongCode(code string) string {
	if code[0] == '0' {
		return "1" + code[1:]
	}
	return "0" + code[1:]
}

// A signed-in user adds a number by confirming a code sent to it. The
// number is written at the confirmation and not before.
func TestPhoneNumberIsAddedByCode(t *testing.T) {
	ctx := context.Background()
	var payloads []behemoth.M
	app := bootPhones(t, waited(phonenumber.Options{SendLimit: types.Limit{Max: 20, Window: time.Minute}}), func(reg types.HookRegistry) error {
		return reg.OnBefore(phonenumber.HookSendBefore, func(_ *types.HookContext, p behemoth.M) (behemoth.M, error) {
			payloads = append(payloads, p)
			return nil, nil
		}, nil)
	})
	ada := app.signUp(t, "ada@example.com")

	sent, err := app.phones.SendCode(ctx, phonenumber.SendRequest{
		PhoneNumber: "  " + adaNumber + " ", UserID: ada.ID, Metadata: behemoth.M{"locale": "en"},
	})
	require.NoError(t, err)
	assert.True(t, sent.Sent)
	assert.Equal(t, phonenumber.PurposeVerify, sent.Purpose)
	assert.Equal(t, adaNumber, sent.PhoneNumber)
	require.Len(t, payloads, 1)
	assert.Equal(t, behemoth.M{"phone_number": adaNumber, "purpose": "verify", "userID": ada.ID}, payloads[0])

	msg := app.sms.last(t, 1)
	assert.Equal(t, types.SMSPhoneVerification, msg.Kind)
	assert.Equal(t, adaNumber, msg.To)
	assert.Len(t, msg.Code, 6)
	assert.Equal(t, ada.ID, msg.User.ID)
	assert.Equal(t, behemoth.M{"locale": "en"}, msg.Metadata)
	assert.WithinDuration(t, time.Now().Add(5*time.Minute), msg.ExpiresAt, 10*time.Second)
	_, has := app.numberOf(t, ada.ID)
	assert.False(t, has, "asking for a code writes nothing")
	var stored string
	require.NoError(t, app.db.QueryRow(`SELECT code_hash FROM verification_codes WHERE subject = ?`, ada.ID).Scan(&stored))
	assert.NotContains(t, stored, msg.Code, "only a hash of the code is stored")

	// The code is for the number it was sent to, and for this user.
	_, err = app.phones.AddNumber(ctx, ada.ID, graceNumber, msg.Code)
	assert.True(t, invalidPhoneCode(err), "another number: %v", err)
	_, err = app.phones.AddNumber(ctx, ada.ID, adaNumber, msg.Code)
	assert.True(t, invalidPhoneCode(err), "the mismatch used the code up: %v", err)

	_, err = app.phones.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: adaNumber, UserID: ada.ID})
	require.NoError(t, err)
	msg = app.sms.last(t, 2)
	grace := app.signUp(t, "grace@example.com")
	_, err = app.phones.AddNumber(ctx, grace.ID, adaNumber, msg.Code)
	assert.True(t, invalidPhoneCode(err), "another user: %v", err)

	updated, err := app.phones.AddNumber(ctx, ada.ID, adaNumber, msg.Code)
	require.NoError(t, err)
	number, _, err := phonenumber.Column.Get(updated)
	require.NoError(t, err)
	assert.Equal(t, adaNumber, number)
	_, err = app.phones.AddNumber(ctx, ada.ID, adaNumber, msg.Code)
	assert.True(t, invalidPhoneCode(err), "a code works once: %v", err)

	// What a later request for the same number is told, in code.
	for name, tc := range map[string]struct {
		userID string
		reason string
	}{
		"the holder":   {ada.ID, phonenumber.ReasonAlreadySet},
		"another user": {grace.ID, phonenumber.ReasonNumberTaken},
	} {
		sent, err := app.phones.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: adaNumber, UserID: tc.userID})
		require.NoError(t, err, name)
		assert.False(t, sent.Sent, name)
		assert.Equal(t, tc.reason, sent.Reason, name)
	}
	assert.Equal(t, 2, app.sms.count(), "neither was sent a message")

	// Changing the number replaces it.
	_, err = app.phones.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: graceNumber, UserID: ada.ID})
	require.NoError(t, err)
	_, err = app.phones.AddNumber(ctx, ada.ID, graceNumber, app.sms.last(t, 3).Code)
	require.NoError(t, err)
	number, _ = app.numberOf(t, ada.ID)
	assert.Equal(t, graceNumber, number)

	for _, bad := range []string{"", "4155550101", "+1 415 555 0101", "+0155550101", "+1415", "+14155550101234567", "+1415555010a"} {
		_, err := app.phones.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: bad, UserID: ada.ID})
		assert.True(t, hasCode(err, behemotherr.CategoryValidation, phonenumber.ErrorCodeInvalidPhoneNumber), "%q: %v", bad, err)
	}
}

// A code has five tries, the right one included, and a new code replaces
// the old one.
func TestPhoneCodeAttemptsAndReplacement(t *testing.T) {
	ctx := context.Background()
	app := bootPhones(t, waited(phonenumber.Options{SendLimit: types.Limit{Max: 10, Window: time.Minute}}), nil)
	ada := app.signUp(t, "ada@example.com")
	send := func(n int) string {
		t.Helper()
		_, err := app.phones.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: adaNumber, UserID: ada.ID})
		require.NoError(t, err)
		return app.sms.last(t, n).Code
	}

	code := send(1)
	for range 5 {
		_, err := app.phones.AddNumber(ctx, ada.ID, adaNumber, wrongCode(code))
		assert.True(t, invalidPhoneCode(err), "%v", err)
	}
	_, err := app.phones.AddNumber(ctx, ada.ID, adaNumber, code)
	assert.True(t, invalidPhoneCode(err), "the right code after five wrong ones: %v", err)

	first := send(2)
	second := send(3)
	if first != second {
		_, err = app.phones.AddNumber(ctx, ada.ID, adaNumber, first)
		assert.True(t, invalidPhoneCode(err), "the replaced code: %v", err)
	}
	_, err = app.phones.AddNumber(ctx, ada.ID, adaNumber, second)
	require.NoError(t, err, "the wrong guess at the newer code cost one try, not the code")
}

// The code manager on its own: expiry, concurrent guesses, and a deleted
// user's codes.
func TestCodeManager(t *testing.T) {
	ctx := context.Background()
	app := bootPhones(t, waited(phonenumber.Options{}), nil)
	codes := app.ac.Codes
	const kind types.CodeKind = "test.kind"

	code, issued, err := codes.Issue(ctx, kind, "subject", types.CodeOptions{Length: 8, Metadata: behemoth.M{"note": "x"}})
	require.NoError(t, err)
	assert.Len(t, code, 8)
	assert.Equal(t, 5, issued.AttemptsLeft)
	_, err = codes.Consume(ctx, "test.other", "subject", code)
	assert.True(t, behemotherr.IsCodeRejection(err), "another kind: %v", err)
	_, err = codes.Consume(ctx, kind, "someone else", code)
	assert.True(t, behemotherr.IsCodeRejection(err), "another subject: %v", err)
	consumed, err := codes.Consume(ctx, kind, "subject", code)
	require.NoError(t, err)
	assert.Equal(t, "x", consumed.Metadata["note"])
	_, err = codes.Consume(ctx, kind, "subject", code)
	assert.True(t, behemotherr.IsCodeRejection(err), "used: %v", err)

	code, _, err = codes.Issue(ctx, kind, "subject", types.CodeOptions{TTL: time.Millisecond})
	require.NoError(t, err)
	time.Sleep(20 * time.Millisecond)
	_, err = codes.Consume(ctx, kind, "subject", code)
	assert.True(t, behemotherr.IsCodeRejection(err), "expired: %v", err)
	require.NoError(t, app.ac.Store.PurgeExpiredVerificationCodes(ctx))
	var rows int
	require.NoError(t, app.db.QueryRow(`SELECT COUNT(*) FROM verification_codes`).Scan(&rows))
	assert.Zero(t, rows, "the purge removed the expired code")

	// Guesses arriving together each take a try: with three tries and the
	// right code sent eight times, one succeeds and no more than three ran.
	code, _, err = codes.Issue(ctx, kind, "subject", types.CodeOptions{MaxAttempts: 3})
	require.NoError(t, err)
	var wg sync.WaitGroup
	results := make([]error, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = codes.Consume(ctx, kind, "subject", code)
		}()
	}
	wg.Wait()
	won := 0
	for _, err := range results {
		if err == nil {
			won++
		} else {
			assert.True(t, behemotherr.IsCodeRejection(err), "%v", err)
		}
	}
	assert.Equal(t, 1, won, "the code is used once")

	for _, opts := range []types.CodeOptions{{Length: 3}, {Length: 13}, {MaxAttempts: -1}, {TTL: -time.Second}} {
		_, _, err := codes.Issue(ctx, kind, "subject", opts)
		assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%+v: %v", opts, err)
	}

	// A user's codes go with the user.
	ada := app.signUp(t, "ada@example.com")
	_, _, err = codes.Issue(ctx, kind, ada.ID, types.CodeOptions{})
	require.NoError(t, err)
	require.NoError(t, app.ac.Store.DeleteUser(ctx, ada.ID))
	require.NoError(t, app.db.QueryRow(`SELECT COUNT(*) FROM verification_codes WHERE subject = ?`, ada.ID).Scan(&rows))
	assert.Zero(t, rows)
}

// A user who holds a number signs in with a code sent to it, or with the
// number and their password. Every refusal of one way has one answer.
func TestPhoneNumberSignIn(t *testing.T) {
	ctx := context.Background()
	var before []behemoth.M
	var failed []string
	app := bootPhones(t, waited(phonenumber.Options{}), func(reg types.HookRegistry) error {
		if err := reg.OnBefore(hooks.HookSignInBefore, func(_ *types.HookContext, p behemoth.M) (behemoth.M, error) {
			before = append(before, p)
			return nil, nil
		}, nil); err != nil {
			return err
		}
		return reg.OnFailed(hooks.HookSignInFailed, func(_ *types.HookContext, reason types.FailureReason) error {
			failed = append(failed, reason.Code)
			return nil
		}, nil)
	})
	ada := app.withNumber(t, "ada@example.com", adaNumber)

	// By code.
	sent, err := app.phones.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: adaNumber})
	require.NoError(t, err)
	require.True(t, sent.Sent)
	assert.Equal(t, phonenumber.PurposeSignIn, sent.Purpose)
	msg := app.sms.last(t, 2)
	assert.Equal(t, types.SMSSignIn, msg.Kind)

	_, err = app.phones.AddNumber(ctx, ada.ID, adaNumber, msg.Code)
	assert.True(t, invalidPhoneCode(err), "a sign-in code adds no number: %v", err)

	_, err = app.phones.SignInWithCode(ctx, adaNumber, wrongCode(msg.Code))
	assert.True(t, invalidPhoneCode(err), "%v", err)
	_, err = app.phones.SignInWithCode(ctx, graceNumber, msg.Code)
	assert.True(t, invalidPhoneCode(err), "a number nobody holds: %v", err)
	assert.Equal(t, []string{"invalid_code", "user_not_found"}, failed)

	before = nil
	result, err := app.phones.SignInWithCode(ctx, adaNumber, msg.Code)
	require.NoError(t, err)
	assert.Equal(t, ada.ID, result.User.ID)
	assert.Equal(t, phonenumber.PluginName, result.Method)
	assert.Equal(t, models.SessionActive, result.Session.State)
	assert.NotEmpty(t, result.RawToken)
	assert.Equal(t, []behemoth.M{{"method": "phonenumber", "phone_number": adaNumber}}, before, "the code is not in the payload")
	_, err = app.phones.SignInWithCode(ctx, adaNumber, msg.Code)
	assert.True(t, invalidPhoneCode(err), "a code works once: %v", err)

	// A number nobody holds gets no code, and the caller in code is told.
	sent, err = app.phones.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: graceNumber})
	require.NoError(t, err)
	assert.False(t, sent.Sent)
	assert.Equal(t, phonenumber.ReasonNoAccount, sent.Reason)
	assert.Equal(t, 2, app.sms.count())

	// By password.
	before = nil
	result, err = app.phones.SignIn(ctx, phonenumber.Credentials{PhoneNumber: " " + adaNumber, Password: password, Extra: behemoth.M{"captcha": "x"}})
	require.NoError(t, err)
	assert.Equal(t, ada.ID, result.User.ID)
	assert.Equal(t, phonenumber.PluginName, result.Method)
	assert.Equal(t, []behemoth.M{{"phone_number": adaNumber, "password": password, "captcha": "x"}}, before)

	for name, creds := range map[string]phonenumber.Credentials{
		"wrong password":     {PhoneNumber: adaNumber, Password: "nope"},
		"unknown number":     {PhoneNumber: graceNumber, Password: password},
		"not a phone number": {PhoneNumber: "ada", Password: password},
		"no number":          {Password: password},
	} {
		_, err := app.phones.SignIn(ctx, creds)
		assert.True(t, hasCode(err, behemotherr.CategoryUnauthorized, emailpassword.ErrorCodeInvalidCredentials), "%s: %v", name, err)
	}
}

// A second factor asked for at the shared checkpoint applies to a sign-in
// by code.
func TestPhoneCodeSignInPassesTheSecondFactorCheckpoint(t *testing.T) {
	ctx := context.Background()
	app := bootPhones(t, waited(phonenumber.Options{}), func(reg types.HookRegistry) error {
		return reg.OnBefore(hooks.HookSignInCredentialsVerified, func(_ *types.HookContext, p behemoth.M) (behemoth.M, error) {
			p["requireStepUp"] = true
			return p, nil
		}, nil)
	})
	app.withNumber(t, "ada@example.com", adaNumber)
	_, err := app.phones.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: adaNumber})
	require.NoError(t, err)
	result, err := app.phones.SignInWithCode(ctx, adaNumber, app.sms.last(t, 2).Code)
	require.NoError(t, err)
	assert.Equal(t, models.SessionPending, result.Session.State)
}

// Only the plugin's flows set a number. A direct write is refused, except
// one that removes the number.
func TestPhoneNumberDirectWritesAreRefused(t *testing.T) {
	ctx := context.Background()
	app := bootPhones(t, waited(phonenumber.Options{}), nil)
	ada := app.withNumber(t, "ada@example.com", adaNumber)
	grace := app.signUp(t, "grace@example.com")
	unconfirmed := func(err error) bool {
		return hasCode(err, behemotherr.CategoryForbidden, phonenumber.ErrorCodeUnconfirmedChange)
	}

	_, err := app.ac.Store.UpdateUser(ctx, grace.ID, behemoth.M{phonenumber.Column.Name: graceNumber})
	assert.True(t, unconfirmed(err), "%v", err)
	_, err = app.ac.Store.UpdateUser(ctx, ada.ID, behemoth.M{phonenumber.Column.Name: graceNumber})
	assert.True(t, unconfirmed(err), "a change of an existing number: %v", err)
	_, err = app.ac.Store.UpdateUser(ctx, ada.ID, behemoth.M{phonenumber.Column.Name: adaNumber})
	assert.True(t, unconfirmed(err), "even to the number the user holds: %v", err)
	direct := &models.User{Email: "linus@example.com"}
	require.NoError(t, phonenumber.Column.Set(direct, graceNumber))
	assert.True(t, unconfirmed(app.ac.Store.CreateUser(ctx, direct)), "a create with a number")
	number, _ := app.numberOf(t, ada.ID)
	assert.Equal(t, adaNumber, number, "nothing changed")
	_, has := app.numberOf(t, grace.ID)
	assert.False(t, has)

	// Other columns are not affected, and a user without a number stores
	// NULL.
	_, err = app.ac.Store.UpdateUser(ctx, ada.ID, behemoth.M{models.UserFirstname: "Ada"})
	require.NoError(t, err)
	var stored sql.NullString
	require.NoError(t, app.db.QueryRow(`SELECT phone_number FROM users WHERE id = ?`, grace.ID).Scan(&stored))
	assert.False(t, stored.Valid)

	// The application vouches for a number through SetPhoneNumber.
	updated, err := app.phones.SetPhoneNumber(ctx, grace.ID, graceNumber)
	require.NoError(t, err)
	number, _, _ = phonenumber.Column.Get(updated)
	assert.Equal(t, graceNumber, number)
	_, err = app.phones.SetPhoneNumber(ctx, grace.ID, adaNumber)
	assert.True(t, hasCode(err, behemotherr.CategoryConflict, phonenumber.ErrorCodePhoneNumberTaken), "%v", err)
	_, err = app.phones.SetPhoneNumber(ctx, grace.ID, "0911234567")
	assert.True(t, behemotherr.IsCode(err, phonenumber.ErrorCodeInvalidPhoneNumber), "%v", err)

	// Removing a number passes, directly and through the plugin.
	_, err = app.ac.Store.UpdateUser(ctx, ada.ID, behemoth.M{phonenumber.Column.Name: nil})
	require.NoError(t, err)
	_, has = app.numberOf(t, ada.ID)
	assert.False(t, has)
	_, err = app.phones.SetPhoneNumber(ctx, grace.ID, "")
	require.NoError(t, err)
	_, has = app.numberOf(t, grace.ID)
	assert.False(t, has)
	_, err = app.phones.SignIn(ctx, phonenumber.Credentials{PhoneNumber: adaNumber, Password: password})
	assert.True(t, behemotherr.IsCode(err, emailpassword.ErrorCodeInvalidCredentials), "a removed number no longer signs in: %v", err)
}

// A number another user takes between the code and its confirmation is a
// conflict.
func TestPhoneNumberTakenBeforeConfirmation(t *testing.T) {
	ctx := context.Background()
	app := bootPhones(t, waited(phonenumber.Options{}), nil)
	ada := app.signUp(t, "ada@example.com")
	grace := app.signUp(t, "grace@example.com")

	_, err := app.phones.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: adaNumber, UserID: ada.ID})
	require.NoError(t, err)
	_, err = app.phones.SetPhoneNumber(ctx, grace.ID, adaNumber)
	require.NoError(t, err)
	_, err = app.phones.AddNumber(ctx, ada.ID, adaNumber, app.sms.last(t, 1).Code)
	assert.True(t, hasCode(err, behemotherr.CategoryConflict, phonenumber.ErrorCodePhoneNumberTaken), "%v", err)
}

// Codes are limited per number, whatever they are for and whoever the
// number belongs to.
func TestPhoneCodesAreLimitedPerNumber(t *testing.T) {
	ctx := context.Background()
	app := bootPhones(t, waited(phonenumber.Options{}), nil)
	ada := app.signUp(t, "ada@example.com")

	for range 2 {
		_, err := app.phones.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: adaNumber, UserID: ada.ID})
		require.NoError(t, err)
	}
	_, err := app.phones.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: adaNumber})
	require.NoError(t, err, "the third, for another purpose")
	_, err = app.phones.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: adaNumber, UserID: ada.ID})
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryRateLimited), "the fourth: %v", err)
	assert.Equal(t, 2, app.sms.count())

	// A number nobody holds is counted the same, so the limit does not show
	// which numbers have an account.
	for range 3 {
		_, err := app.phones.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: graceNumber})
		require.NoError(t, err)
	}
	_, err = app.phones.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: graceNumber})
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryRateLimited), "%v", err)
}

// A send the sender refuses leaves no usable code, and one sent in the
// background does not hold the caller up.
func TestPhoneCodeSending(t *testing.T) {
	ctx := context.Background()
	app := bootPhones(t, waited(phonenumber.Options{}), nil)
	ada := app.signUp(t, "ada@example.com")
	app.sms.fail = errors.New("provider down")
	sent, err := app.phones.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: adaNumber, UserID: ada.ID})
	require.NoError(t, err)
	assert.False(t, sent.Sent)
	assert.Equal(t, phonenumber.ReasonSendFailed, sent.Reason)
	var rows int
	require.NoError(t, app.db.QueryRow(`SELECT COUNT(*) FROM verification_codes`).Scan(&rows))
	assert.Zero(t, rows, "the code nobody received is revoked")

	background := bootPhones(t, phonenumber.Options{}, nil)
	grace := background.signUp(t, "grace@example.com")
	sent, err = background.phones.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: graceNumber, UserID: grace.ID})
	require.NoError(t, err)
	assert.True(t, sent.Sent, "queued")
	require.Eventually(t, func() bool { return background.sms.count() == 1 }, 5*time.Second, time.Millisecond)
	_, err = background.phones.AddNumber(ctx, grace.ID, graceNumber, background.sms.last(t, 1).Code)
	require.NoError(t, err)
}

// With the option on, a code sent to the user's number sets a new password.
func TestPhonePasswordReset(t *testing.T) {
	ctx := context.Background()
	var failed []string
	app := bootPhones(t, waited(phonenumber.Options{PasswordReset: true}), func(reg types.HookRegistry) error {
		return reg.OnFailed(phonenumber.HookResetFailed, func(_ *types.HookContext, reason types.FailureReason) error {
			failed = append(failed, reason.Code)
			return nil
		}, nil)
	})
	ada := app.withNumber(t, "ada@example.com", adaNumber)
	session, err := app.passwords.SignIn(ctx, emailpassword.EmailAndPasswordCredentials{Email: "ada@example.com", Password: password})
	require.NoError(t, err)

	sent, err := app.phones.RequestPasswordReset(ctx, phonenumber.ResetRequest{PhoneNumber: graceNumber})
	require.NoError(t, err)
	assert.Equal(t, phonenumber.ReasonNoAccount, sent.Reason)
	sent, err = app.phones.RequestPasswordReset(ctx, phonenumber.ResetRequest{PhoneNumber: adaNumber})
	require.NoError(t, err)
	require.True(t, sent.Sent)
	assert.Equal(t, phonenumber.PurposePasswordReset, sent.Purpose)
	msg := app.sms.last(t, 2)
	assert.Equal(t, types.SMSPasswordReset, msg.Kind)

	_, err = app.phones.SignInWithCode(ctx, adaNumber, msg.Code)
	assert.True(t, invalidPhoneCode(err), "a reset code does not sign in: %v", err)

	// A refused password costs the code nothing.
	for range 6 {
		_, err = app.phones.ResetPassword(ctx, adaNumber, msg.Code, "short")
		assert.True(t, hasCode(err, behemotherr.CategoryValidation, emailpassword.ErrorCodeInvalidPassword), "%v", err)
	}
	_, err = app.phones.ResetPassword(ctx, graceNumber, msg.Code, "a new password")
	assert.True(t, invalidPhoneCode(err), "a number nobody holds: %v", err)
	_, err = app.phones.ResetPassword(ctx, adaNumber, wrongCode(msg.Code), "a new password")
	assert.True(t, invalidPhoneCode(err), "%v", err)
	assert.Equal(t, []string{"no_account", "invalid_code"}, failed)

	user, err := app.phones.ResetPassword(ctx, adaNumber, msg.Code, "a new password")
	require.NoError(t, err)
	assert.Equal(t, ada.ID, user.ID)
	_, err = app.phones.ResetPassword(ctx, adaNumber, msg.Code, "another password")
	assert.True(t, invalidPhoneCode(err), "a code works once: %v", err)

	_, err = app.phones.SignIn(ctx, phonenumber.Credentials{PhoneNumber: adaNumber, Password: password})
	assert.True(t, behemotherr.IsCode(err, emailpassword.ErrorCodeInvalidCredentials), "the old password: %v", err)
	_, err = app.phones.SignIn(ctx, phonenumber.Credentials{PhoneNumber: adaNumber, Password: "a new password"})
	require.NoError(t, err)
	_, err = app.ac.SessionManager.Validate(ctx, session.RawToken)
	assert.Error(t, err, "the sessions made with the old password ended")

	// Off by default: no routes, and the flows say so.
	off := bootPhones(t, waited(phonenumber.Options{}), nil)
	_, mounted := off.routes["/api/auth"+phonenumber.PathReset]
	assert.False(t, mounted)
	_, mounted = off.routes["/api/auth"+phonenumber.PathResetRequest]
	assert.False(t, mounted)
	_, err = off.phones.RequestPasswordReset(ctx, phonenumber.ResetRequest{PhoneNumber: adaNumber})
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%v", err)
	_, err = off.phones.ResetPassword(ctx, adaNumber, "123456", "a new password")
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%v", err)
}

// The routes: send and verify act for the caller's session when there is
// one and sign in when there is none, and what a client may not learn is
// the same answer.
func TestPhoneNumberRoutes(t *testing.T) {
	ctx := context.Background()
	app := bootPhones(t, waited(phonenumber.Options{PasswordReset: true}), nil)
	route := func(path string) types.Route {
		r, ok := app.routes["/api/auth"+path]
		require.True(t, ok, path)
		return r
	}
	type answer struct {
		User   map[string]any `json:"user"`
		Status string         `json:"status"`
		Code   string         `json:"code"`
		Token  string         `json:"token"`
	}
	read := func(body []byte) answer {
		t.Helper()
		var a answer
		require.NoError(t, json.Unmarshal(body, &a), string(body))
		return a
	}
	ok := `{"status":"ok"}`

	app.signUp(t, "ada@example.com")
	signedIn, err := app.passwords.SignIn(ctx, emailpassword.EmailAndPasswordCredentials{Email: "ada@example.com", Password: password})
	require.NoError(t, err)
	session := signedIn.RawToken

	// With a session: add the number.
	w := callAs(t, app.ac, route(phonenumber.PathSendOTP), `{"phone_number":"`+adaNumber+`","metadata":{"locale":"en"}}`, session)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, ok, w.Body.String())
	msg := app.sms.last(t, 1)
	assert.Equal(t, types.SMSPhoneVerification, msg.Kind)
	assert.Equal(t, behemoth.M{"locale": "en"}, msg.Metadata)

	w = callAs(t, app.ac, route(phonenumber.PathVerify), `{"phone_number":"`+adaNumber+`","code":"`+wrongCode(msg.Code)+`"}`, session)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	assert.Equal(t, phonenumber.ErrorCodeInvalidCode, read(w.Body.Bytes()).Code)
	w = callAs(t, app.ac, route(phonenumber.PathVerify), `{"phone_number":"`+adaNumber+`","code":"`+msg.Code+`"}`, session)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	added := read(w.Body.Bytes())
	assert.Equal(t, adaNumber, added.User["phone_number"], "the column is public")
	assert.Empty(t, w.Header().Get("Set-Auth-Token"), "adding a number creates no session")

	// Without a session: sign in. A number nobody holds is answered the
	// same at the send, and with the one code error at the verify.
	for _, number := range []string{adaNumber, graceNumber} {
		w = callAs(t, app.ac, route(phonenumber.PathSendOTP), `{"phone_number":"`+number+`"}`, "")
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.JSONEq(t, ok, w.Body.String(), number)
	}
	msg = app.sms.last(t, 2)
	assert.Equal(t, types.SMSSignIn, msg.Kind)
	w = callAs(t, app.ac, route(phonenumber.PathVerify), `{"phone_number":"`+graceNumber+`","code":"`+msg.Code+`"}`, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	assert.Equal(t, phonenumber.ErrorCodeInvalidCode, read(w.Body.Bytes()).Code)
	w = callAs(t, app.ac, route(phonenumber.PathVerify), `{"phone_number":"`+adaNumber+`","code":"`+msg.Code+`"}`, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "ada@example.com", read(w.Body.Bytes()).User["email"])
	assert.NotEmpty(t, w.Header().Get("Set-Auth-Token"), "the token travels by the configured transport")
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))

	// A session token that is no good is refused, not ignored.
	w = callAs(t, app.ac, route(phonenumber.PathSendOTP), `{"phone_number":"`+graceNumber+`"}`, "not-a-session")
	assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	// Password sign-in.
	w = callAs(t, app.ac, route(phonenumber.PathSignIn), `{"phone_number":"`+adaNumber+`","password":"`+password+`"}`, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.NotEmpty(t, w.Header().Get("Set-Auth-Token"))
	for _, body := range []string{
		`{"phone_number":"` + adaNumber + `","password":"nope"}`,
		`{"phone_number":"` + graceNumber + `","password":"` + password + `"}`,
	} {
		w = callAs(t, app.ac, route(phonenumber.PathSignIn), body, "")
		require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
		assert.Equal(t, emailpassword.ErrorCodeInvalidCredentials, read(w.Body.Bytes()).Code)
	}

	// Password reset.
	for _, number := range []string{adaNumber, graceNumber} {
		w = callAs(t, app.ac, route(phonenumber.PathResetRequest), `{"phone_number":"`+number+`"}`, "")
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.JSONEq(t, ok, w.Body.String(), number)
	}
	msg = app.sms.last(t, 3)
	w = callAs(t, app.ac, route(phonenumber.PathReset), `{"phone_number":"`+adaNumber+`","code":"`+msg.Code+`","password":"x"}`, "")
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Equal(t, emailpassword.ErrorCodeInvalidPassword, read(w.Body.Bytes()).Code)
	w = callAs(t, app.ac, route(phonenumber.PathReset), `{"phone_number":"`+adaNumber+`","code":"`+msg.Code+`","password":"a new password"}`, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `{"status":"password_reset"}`, w.Body.String())
	assert.Empty(t, w.Header().Get("Set-Auth-Token"), "a reset does not sign in")

	// Validation, on every route.
	for path, body := range map[string]string{
		phonenumber.PathSendOTP:      `{"phone_number":"0911234567"}`,
		phonenumber.PathVerify:       `{"phone_number":7,"code":"123456"}`,
		phonenumber.PathSignIn:       `{"phone_number":7,"password":"x"}`,
		phonenumber.PathResetRequest: `{"phone_number":"nope"}`,
		phonenumber.PathReset:        `{"phone_number":"nope","code":"1","password":"a new password"}`,
	} {
		w = callAs(t, app.ac, route(path), body, "")
		require.Equal(t, http.StatusBadRequest, w.Code, "%s: %s", path, w.Body.String())
		assert.Equal(t, phonenumber.ErrorCodeInvalidPhoneNumber, read(w.Body.Bytes()).Code, path)
		assert.Equal(t, http.StatusBadRequest, callAs(t, app.ac, route(path), `{`, "").Code, path)
	}
}

func TestPhoneNumberOptionsAndWiring(t *testing.T) {
	ctx := context.Background()
	passwords := emailpassword.New(emailpassword.Options{})

	meta := phonenumber.New(passwords, phonenumber.Options{}).Meta()
	assert.Equal(t, phonenumber.PluginName, meta.Name)
	assert.Equal(t, []types.PluginDependency{{Name: emailpassword.PluginName}}, meta.Dependencies)

	// Boot fails without an SMS sender.
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "nosms.db"))
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(phoneSchema)
	require.NoError(t, err)
	prepared, err := bmth.Prepare([]types.Plugin{passwords, phonenumber.New(passwords, phonenumber.Options{})}, bmth.PrepareConfig{})
	require.NoError(t, err)
	_, err = bmth.Boot(ctx, prepared, sqliteAdapter.NewSQLiteAdapter(db, prepared.Resolver), bmth.BootConfig{
		Crypto: crypto.Config{
			Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ef", 32)}, Current: 1},
		},
	})
	require.Error(t, err)
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%v", err)
	assert.Contains(t, err.Error(), "SMS")

	app := bootPhones(t, waited(phonenumber.Options{}), nil)
	for name, p := range map[string]*phonenumber.Plugin{
		"no email/password plugin": phonenumber.New(nil, phonenumber.Options{}),
		"a short code":             phonenumber.New(passwords, phonenumber.Options{CodeLength: 2}),
		"no attempts":              phonenumber.New(passwords, phonenumber.Options{MaxAttempts: -1}),
		"a negative lifetime":      phonenumber.New(passwords, phonenumber.Options{CodeTTL: -time.Minute}),
	} {
		err := p.Init(app.ac)
		require.Error(t, err, name)
		assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%s: %v", name, err)
	}

	unbooted := phonenumber.New(passwords, phonenumber.Options{})
	_, err = unbooted.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: adaNumber})
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%v", err)
	_, err = unbooted.SetPhoneNumber(ctx, "id", adaNumber)
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%v", err)

	// The options reach the code.
	custom := bootPhones(t, waited(phonenumber.Options{CodeLength: 8, CodeTTL: time.Hour}), nil)
	ada := custom.signUp(t, "ada@example.com")
	_, err = custom.phones.SendCode(ctx, phonenumber.SendRequest{PhoneNumber: adaNumber, UserID: ada.ID})
	require.NoError(t, err)
	msg := custom.sms.last(t, 1)
	assert.Len(t, msg.Code, 8)
	assert.WithinDuration(t, time.Now().Add(time.Hour), msg.ExpiresAt, 10*time.Second)
}
