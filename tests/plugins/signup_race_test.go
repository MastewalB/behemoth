package plugins_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/clause"
	"github.com/go-behemoth/behemoth/core"
	"github.com/go-behemoth/behemoth/core/hooks"
	"github.com/go-behemoth/behemoth/crypto"
	"github.com/go-behemoth/behemoth/engine"
	"github.com/go-behemoth/behemoth/errs"
	"github.com/go-behemoth/behemoth/httpapi"
	"github.com/go-behemoth/behemoth/models"
	"github.com/go-behemoth/behemoth/plugins/emailpassword"
	"github.com/go-behemoth/behemoth/plugins/username"
	sqliteAdapter "github.com/go-behemoth/behemoth/storage/adapters/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A write that loses a race for a unique column of users: a flow checks the
// value, another write takes it, and the database refuses the flow's write.
// The loser gets the code it would have got had its check seen the winner
// (docs/internal/database/adapters/unique_keys.md).
//
// A race is made deterministic with lookupGap, a Database that acts on one
// lookup of a user: the check a flow makes before it inserts.

// lookupGap is a Database that, on the first lookup of a user by column and
// value, lets another write land between the check and the insert that
// follows it. Lookups inside a transaction go through it too.
type lookupGap struct {
	behemoth.Database
	gap *gap
}

type gap struct {
	column string
	value  any
	// during runs right after the lookup, before its result is returned:
	// another sign-up that commits in the gap.
	during func()
	// stale makes the lookup find no user, as one that ran just before the
	// other write committed would. It is for a check inside a transaction
	// that holds SQLite's write lock, where nothing else can commit in the
	// gap; a database without that lock (PostgreSQL by default) lets it.
	stale bool
	fired atomic.Bool
}

// open arms the gap for the next lookup of a user by column and value.
func (g *lookupGap) open(column string, value any, stale bool, during func()) {
	g.gap = &gap{column: column, value: value, stale: stale, during: during}
}

func (g *lookupGap) FindOne(ctx context.Context, model behemoth.Model, expr clause.Expression) (behemoth.Model, error) {
	if !g.gap.takes(model, expr) {
		return g.Database.FindOne(ctx, model, expr)
	}
	if g.gap.stale {
		return nil, errs.NewNotFound("FindOne", models.UserTable, nil)
	}
	found, err := g.Database.FindOne(ctx, model, expr)
	if g.gap.during != nil {
		g.gap.during()
	}
	return found, err
}

func (g *lookupGap) Transaction(ctx context.Context, fn behemoth.TransactionFunc) error {
	return g.Database.Transaction(ctx, func(txCtx context.Context, tx behemoth.Database) (any, error) {
		return fn(txCtx, &lookupGap{Database: tx, gap: g.gap})
	})
}

// takes reports whether a lookup is the one the gap is for, the first time
// it is made.
func (g *gap) takes(model behemoth.Model, expr clause.Expression) bool {
	if g == nil {
		return false
	}
	if _, isUser := model.(*models.User); !isUser {
		return false
	}
	for _, c := range expr.Conditions {
		if c.Field == g.column && c.Value == g.value {
			return g.fired.CompareAndSwap(false, true)
		}
	}
	return false
}

type raceApp struct {
	ac        *core.AuthContext
	passwords *emailpassword.Plugin
	names     *username.Plugin
	db        *lookupGap
}

// bootRace boots the email/password plugin, and the username plugin when
// withUsernames is set, over a lookupGap. The SQLite settings are those of
// bootUsernames.
func bootRace(t *testing.T, withUsernames bool, hookFn func(reg core.HookRegistry) error) *raceApp {
	t.Helper()
	sqlDB, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "race.db")+"?_foreign_keys=on&_busy_timeout=10000&_txlock=immediate")
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() })
	_, err = sqlDB.Exec(usernameSchema)
	require.NoError(t, err)

	app := &raceApp{passwords: emailpassword.New(emailpassword.Options{})}
	plugins := []core.Plugin{app.passwords}
	if withUsernames {
		app.names = username.New(app.passwords, username.Options{})
		plugins = []core.Plugin{app.names, app.passwords}
	}
	prepared, err := engine.Prepare(plugins, engine.PrepareConfig{})
	require.NoError(t, err)
	app.db = &lookupGap{Database: sqliteAdapter.NewSQLiteAdapter(sqlDB, prepared.Resolver)}
	app.ac, err = engine.Boot(context.Background(), prepared, app.db, engine.BootConfig{
		Crypto: crypto.Config{
			Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ef", 32)}, Current: 1},
		},
		Router: httpapi.RouterConfig{Carrier: httpapi.TokenCarrierConfig{Delivery: httpapi.DeliveryHeader}},
		Hooks:  hookFn,
	})
	require.NoError(t, err)
	return app
}

func (app *raceApp) signUp(t *testing.T, email, name string) (*models.User, error) {
	t.Helper()
	in := behemoth.M{"email": email, "password": "correct horse"}
	if name != "" {
		in["username"] = name
	}
	return app.passwords.SignUp(context.Background(), in)
}

// Two sign-ups for one new email: the second commits between the first one's
// lookup and its insert. The first is refused as a sign-up for a taken
// email is, with email_taken and auth.signUp.failed (user_exists).
func TestSignUpThatLosesTheRaceForAnEmail(t *testing.T) {
	var failed []core.FailureReason
	app := bootRace(t, false, func(reg core.HookRegistry) error {
		return reg.OnFailed(hooks.HookSignUpFailed, func(_ *core.HookContext, reason core.FailureReason) error {
			failed = append(failed, reason)
			return nil
		}, nil)
	})
	var winner *models.User
	app.db.open(models.UserEmail, "ada@example.com", false, func() {
		var err error
		winner, err = app.signUp(t, "ada@example.com", "")
		require.NoError(t, err, "the other sign-up wins")
	})

	_, err := app.signUp(t, "Ada@example.com", "")
	require.NotNil(t, winner, "the other sign-up ran in the gap")
	assert.True(t, hasCode(err, errs.CategoryConflict, emailpassword.ErrorCodeEmailTaken),
		"the loser gets email_taken, as for a taken email; got %v", err)
	if assert.Len(t, failed, 1, "auth.signUp.failed fires for the loser") {
		assert.Equal(t, "user_exists", failed[0].Code)
		assert.Equal(t, "ada@example.com", failed[0].Metadata[hooks.HookValueEmail])
	}

	users, err := app.ac.Store.FindUserByEmail(context.Background(), "ada@example.com")
	require.NoError(t, err)
	assert.Equal(t, winner.ID, users.ID, "the winner keeps the email")
}

// Two sign-ups for one username: the other sign-up committed after the
// username plugin's check and before the insert. The loser is refused with
// username_taken, as when the check sees the holder.
func TestSignUpThatLosesTheRaceForAUsername(t *testing.T) {
	app := bootRace(t, true, nil)
	_, err := app.signUp(t, "eve@example.com", "ada")
	require.NoError(t, err, "the other sign-up wins")

	app.db.open(username.Column.Name, "ada", true, nil)
	_, err = app.signUp(t, "ada@example.com", "Ada")
	assert.True(t, hasCode(err, errs.CategoryConflict, username.ErrorCodeUsernameTaken),
		"the loser gets username_taken; got %v", err)

	_, err = app.ac.Store.FindUserByEmail(context.Background(), "ada@example.com")
	assert.True(t, errs.IsNotFound(err), "the loser has no user: %v", err)
}

// Two SetUsername calls racing for one name: the other user took it
// after this call's check and before its update. The call is refused with
// username_taken.
func TestSetUsernameThatLosesTheRace(t *testing.T) {
	app := bootRace(t, true, nil)
	_, err := app.signUp(t, "eve@example.com", "ada")
	require.NoError(t, err, "the other user holds the name")
	grace, err := app.signUp(t, "grace@example.com", "")
	require.NoError(t, err)

	app.db.open(username.Column.Name, "ada", true, nil)
	_, err = app.names.SetUsername(asAdmin(context.Background()), grace.ID, "ada")
	assert.True(t, hasCode(err, errs.CategoryConflict, username.ErrorCodeUsernameTaken),
		"the loser gets username_taken; got %v", err)
}
