package auth

import (
	"fmt"
	"regexp"
	"sort"
	"sync"

	"github.com/go-behemoth/behemoth/core"
	"github.com/go-behemoth/behemoth/errs"
)

// permissionName is the form of a permission's name: resource:action, each
// part in lowercase snake case.
var permissionName = regexp.MustCompile(`^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$`)

// DefaultPermissionCatalog is the PermissionCatalog Prepare fills and
// freezes.
type DefaultPermissionCatalog struct {
	mu          sync.RWMutex
	permissions map[core.Permission]core.PermissionDef
	frozen      bool
}

// NewDefaultPermissionCatalog returns an empty catalog.
func NewDefaultPermissionCatalog() *DefaultPermissionCatalog {
	return &DefaultPermissionCatalog{permissions: map[core.Permission]core.PermissionDef{}}
}

// Declare implements [core.PermissionCatalog].
func (c *DefaultPermissionCatalog) Declare(def core.PermissionDef) error {
	const op = "PermissionCatalog.Declare"
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.frozen {
		return errs.NewConfigurationError(op, "cannot Declare after boot has completed", nil)
	}
	if !permissionName.MatchString(string(def.Name)) {
		return errs.NewConfigurationError(op, fmt.Sprintf("permission %q is not of the form resource:action in lowercase snake case", def.Name), nil)
	}
	if def.Owner == "" {
		return errs.NewConfigurationError(op, fmt.Sprintf("permission %q missing Owner", def.Name), nil)
	}
	if def.Kind != core.PermissionSelf && def.Kind != core.PermissionAdmin {
		return errs.NewConfigurationError(op, fmt.Sprintf("permission %q declared with invalid or missing Kind %q", def.Name, def.Kind), nil)
	}
	if def.Description == "" {
		return errs.NewConfigurationError(op, fmt.Sprintf("permission %q has no Description", def.Name), nil)
	}
	if existing, dup := c.permissions[def.Name]; dup {
		return errs.NewConfigurationError(op, fmt.Sprintf("permission %q already declared by %q, cannot redeclare from %q", def.Name, existing.Owner, def.Owner), nil)
	}
	c.permissions[def.Name] = def
	return nil
}

// Lookup implements [core.PermissionCatalog].
func (c *DefaultPermissionCatalog) Lookup(p core.Permission) (core.PermissionDef, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	def, ok := c.permissions[p]
	return def, ok
}

// All implements [core.PermissionCatalog].
func (c *DefaultPermissionCatalog) All() []core.PermissionDef {
	c.mu.RLock()
	defer c.mu.RUnlock()
	all := make([]core.PermissionDef, 0, len(c.permissions))
	for _, def := range c.permissions {
		all = append(all, def)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
	return all
}

// Freeze ends the declarations: a later Declare is a configuration error.
func (c *DefaultPermissionCatalog) Freeze() { c.mu.Lock(); c.frozen = true; c.mu.Unlock() }

var _ core.PermissionCatalog = (*DefaultPermissionCatalog)(nil)
