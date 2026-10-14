package main

import (
	"net/http"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
	"github.com/MastewalB/behemoth/types/schema"
	"github.com/MastewalB/behemoth/utils"
)

// ActivityPlugin is a minimal third-party plugin that owns one table. It
// exists to show how a plugin declares a table and fills it from hooks: it
// keeps a row per sign-up and per rejected sign-up or sign-in, the raw
// material of an activity feed. It is unrelated to behemoth's own audit
// trail, which core records in the audit_log table (see audit.go and
// docs/api/telemetry.md).
//
// It declares its table in Declare, next to hooks, tokens and rate limits, so Prepare
// collects it for migrations and the resolver without booting anything.
//
// In Register it hooks the email/password flows and the user write to fill
// that table. It imports neither: the point names are all it shares with
// them.
type ActivityPlugin struct {
	ac *types.AuthContext
}

var _ types.Plugin = (*ActivityPlugin)(nil)

func (p *ActivityPlugin) Meta() types.PluginMeta {
	return types.PluginMeta{Name: "activity", MountPath: "/activity"}
}
func (p *ActivityPlugin) Version() string { return "0.1.0" }

func (p *ActivityPlugin) Declare(ic *types.PluginInitContext) error {
	return ic.Schemas.Declare(&ActivityEvent{}, schema.Table{
		Name: "activity_events",
		Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeUuid, PrimaryKey: true},
			{Name: "type", Type: schema.ColTypeString, Length: 64},
			{Name: "created_at", Type: schema.ColTypeTimestamp},
		},
		Indexes: []schema.Index{{Name: "idx_activity_events_type", Columns: []string{"type"}}},
	})
}

// Keys the plugin's handlers use in HookContext.Values. They carry the
// plugin's name: every handler of an operation shares the map.
const (
	valueStarted = "activity.started" // time.Time: when the sign-up began
)

// Register attaches the plugin's handlers. Three things are on show:
//
//   - A note left on a before point is read on the after point of the same
//     operation (valueStarted, from auth.signUp.before to auth.signUp.after).
//   - A data hook writes through HookContext.Tx, so its row commits or rolls
//     back with the user.
//   - Handlers take the event type from HookContext.Point, which the
//     dispatcher sets.
func (p *ActivityPlugin) Register(reg types.HookRegistry) error {
	// PriorityHighest: the clock starts before any other handler runs,
	// including the application's invite check.
	first := &types.HookOptions{Priority: types.PriorityHighest}
	if err := reg.OnBefore(hooks.HookSignUpBefore, func(hctx *types.HookContext, payload behemoth.M) (behemoth.M, error) {
		hctx.Values[valueStarted] = time.Now()
		trace("activity", hctx, "clock started")
		return payload, nil
	}, first); err != nil {
		return err
	}

	// Tier 1, inside the user's transaction. The write is its own operation
	// and starts with a copy of the sign-up's Values, so valueStarted is
	// visible here. A failure would roll the user back.
	if err := reg.OnAfter(hooks.HookUserAfterCreate, func(hctx *types.HookContext, _ any) error {
		trace("activity", hctx, "activity row written in the user's transaction")
		return hctx.Tx.DB().Create(hctx.Ctx, newActivityEvent(hctx.Point))
	}, nil); err != nil {
		return err
	}

	// Tier 2, after commit. The same map the before handler wrote to.
	if err := reg.OnAfter(hooks.HookSignUpAfter, func(hctx *types.HookContext, _ any) error {
		took := "unknown"
		if started, ok := hctx.Values[valueStarted].(time.Time); ok {
			took = time.Since(started).Round(time.Millisecond).String()
		}
		trace("activity", hctx, "sign-up took "+took)
		return nil
	}, nil); err != nil {
		return err
	}

	// Rejections of both flows. No transaction here, so the row goes
	// through the root adapter.
	failed := func(hctx *types.HookContext, reason types.FailureReason) error {
		trace("activity", hctx, "rejected: "+reason.Code)
		return hctx.Auth.DB.Create(hctx.Ctx, newActivityEvent(hctx.Point))
	}
	if err := reg.OnFailed(hooks.HookSignUpFailed, failed, nil); err != nil {
		return err
	}
	return reg.OnFailed(hooks.HookSignInFailed, failed, nil)
}

func (p *ActivityPlugin) Middlewares() []types.Middleware { return nil }

// Routes are mounted under BasePath + MountPath: GET /api/auth/activity/status.
func (p *ActivityPlugin) Routes() []types.Route {
	return []types.Route{{Method: http.MethodGet, Path: "/status", Handler: p.status}}
}

func (p *ActivityPlugin) status(rctx *types.RequestContext) error {
	return rctx.Response.JSON(http.StatusOK, behemoth.M{
		"plugin":       "activity",
		"auth_context": rctx.Auth != nil && rctx.Auth.SessionManager != nil,
	})
}

func (p *ActivityPlugin) Init(ac *types.AuthContext) error {
	p.ac = ac
	return nil
}

// ActivityEvent is a row of the plugin's table. Type is the hook point that
// recorded it.
type ActivityEvent struct {
	ID        string
	Type      string
	CreatedAt time.Time
}

func newActivityEvent(point types.HookPoint) *ActivityEvent {
	return &ActivityEvent{ID: utils.GenerateUUID(), Type: string(point), CreatedAt: time.Now().UTC()}
}

func (e *ActivityEvent) SchemaName() string     { return "activity_events" }
func (e *ActivityEvent) PrimaryKeyName() string { return "id" }
func (e *ActivityEvent) PrimaryKeyField() any   { return e.ID }
func (e *ActivityEvent) New() behemoth.Model    { return &ActivityEvent{} }

// ToMap and FromMap make the model writable through the database adapter,
// which works on rows keyed by canonical column name.
func (e *ActivityEvent) ToMap() (map[string]any, error) {
	return map[string]any{"id": e.ID, "type": e.Type, "created_at": e.CreatedAt}, nil
}

func (e *ActivityEvent) FromMap(row map[string]any) error {
	e.ID, _ = row["id"].(string)
	e.Type, _ = row["type"].(string)
	e.CreatedAt, _ = row["created_at"].(time.Time)
	return nil
}
