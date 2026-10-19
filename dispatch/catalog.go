package dispatch

import (
	"fmt"
	"sync"

	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/types"
)

type DefaultHookCatalog struct {
	mu     sync.RWMutex
	points map[types.HookPoint]types.HookPointDef
	frozen bool
}

func NewDefaultHookCatalog() *DefaultHookCatalog {
	return &DefaultHookCatalog{points: map[types.HookPoint]types.HookPointDef{}}
}

func (c *DefaultHookCatalog) Declare(def types.HookPointDef) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.frozen {
		return errs.NewConfigurationError("HookCatalog.Declare", "cannot Declare after boot has completed", nil)
	}
	if def.Point == "" {
		return errs.NewConfigurationError("HookCatalog.Declare", "HookPointDef.Point must not be empty", nil)
	}
	if def.Owner == "" {
		return errs.NewConfigurationError("HookCatalog.Declare", fmt.Sprintf("point %q missing Owner", def.Point), nil)
	}
	if def.Phase != types.BeforeHookPhase && def.Phase != types.AfterHookPhase && def.Phase != types.FailedHookPhase {
		return errs.NewConfigurationError("HookCatalog.Declare", fmt.Sprintf("point %q declared with invalid or missing Phase %q", def.Point, def.Phase), nil)
	}
	if existing, dup := c.points[def.Point]; dup {
		return errs.NewConfigurationError("HookCatalog.Declare", fmt.Sprintf("point %q already declared by %q, cannot redeclare from %q", def.Point, existing.Owner, def.Owner), nil)
	}
	c.points[def.Point] = def
	return nil
}

func (c *DefaultHookCatalog) Lookup(point types.HookPoint) (types.HookPointDef, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	def, ok := c.points[point]
	return def, ok
}

func (c *DefaultHookCatalog) Freeze() { c.mu.Lock(); c.frozen = true; c.mu.Unlock() }

// All is consumed only by freezeAllHookChains, to know the full universe of
// declared points, including ones with zero registered handlers, which
// still need an empty (not missing) entry in frozenChains.
func (c *DefaultHookCatalog) All() []types.HookPointDef {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]types.HookPointDef, 0, len(c.points))
	for _, def := range c.points {
		out = append(out, def)
	}
	return out
}
