package main

import (
	"net/http"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/schema"
)

// AuditLogPlugin is a minimal third-party plugin that owns one table. It
// declares it in Declare, next to hooks, tokens and rate limits, so Prepare
// collects it for migrations and the resolver without booting anything.
type AuditLogPlugin struct {
	ac *types.AuthContext
}

var _ types.Plugin = (*AuditLogPlugin)(nil)

func (p *AuditLogPlugin) Meta() types.PluginMeta {
	return types.PluginMeta{Name: "auditlog", MountPath: "/audit"}
}
func (p *AuditLogPlugin) Version() string { return "0.1.0" }

func (p *AuditLogPlugin) Declare(ic *types.PluginInitContext) error {
	return ic.Schemas.Declare(&AuditEvent{}, schema.Table{
		Name: "audit_events",
		Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeUuid, PrimaryKey: true},
			{Name: "type", Type: schema.ColTypeString, Length: 64},
			{Name: "created_at", Type: schema.ColTypeTimestamp},
		},
		Indexes: []schema.Index{{Name: "idx_audit_events_type", Columns: []string{"type"}}},
	})
}

func (p *AuditLogPlugin) Register(reg types.HookRegistry) error { return nil }
func (p *AuditLogPlugin) RegisterHooks() []types.Listener       { return nil }
func (p *AuditLogPlugin) Middlewares() []types.Middleware       { return nil }

// Routes are mounted under BasePath + MountPath: GET /api/auth/audit/status.
func (p *AuditLogPlugin) Routes() []types.Route {
	return []types.Route{{Method: http.MethodGet, Path: "/status", Handler: p.status}}
}

func (p *AuditLogPlugin) status(rctx *types.RequestContext) error {
	return rctx.Response.JSON(http.StatusOK, behemoth.M{
		"plugin":       "auditlog",
		"auth_context": rctx.Auth != nil && rctx.Auth.SessionManager != nil,
	})
}

func (p *AuditLogPlugin) Init(ac *types.AuthContext) error {
	p.ac = ac
	return nil
}

type AuditEvent struct {
	ID   string
	Type string
}

func (e *AuditEvent) SchemaName() string     { return "audit_events" }
func (e *AuditEvent) PrimaryKeyName() string { return "id" }
func (e *AuditEvent) PrimaryKeyField() any   { return e.ID }
func (e *AuditEvent) New() behemoth.Model    { return &AuditEvent{} }
