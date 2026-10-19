package ratelimit

import (
	"errors"
	"fmt"
	"sync"

	"github.com/MastewalB/behemoth/types"
)

type DefaultRateLimitCatalog struct {
	frozen      bool
	mu          sync.RWMutex
	hookCatalog types.HookCatalog // read-only reference, for cross-validating Point at Declare time

	rules      map[types.HookPoint][]types.HookRateLimitRule
	routeRules []types.RouteRateLimitRule
	names      map[string]bool
}

func NewRateLimitCatalog(hooks types.HookCatalog) *DefaultRateLimitCatalog {
	return &DefaultRateLimitCatalog{
		hookCatalog: hooks,
		rules:       map[types.HookPoint][]types.HookRateLimitRule{},
		names:       map[string]bool{},
	}
}

func (c *DefaultRateLimitCatalog) DeclareHookRateLimitRule(rule types.HookRateLimitRule) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.frozen {
		return errors.New("ratelimitcatalog: cannot Declare after boot has completed")
	}

	if rule.Name == "" {
		return errors.New("ratelimit: rule must have a Name")
	}
	if rule.Owner == "" {
		return fmt.Errorf("ratelimit: rule %q missing Owner", rule.Name)
	}
	if c.names[rule.Name] {
		return fmt.Errorf("ratelimit: rule %q already declared", rule.Name)
	}
	if err := checkRateLimitRule(rule.Name, rule.Action, rule.Algorithm, rule.Limiter, rule.Limit); err != nil {
		return err
	}

	// cross-validation: the point must already exist (declared by core, or by an earlier-in-dependency-order plugin, or by
	// this plugin earlier in its own Declare() call), and it must specifically be a Before-phase point, since
	// RunBefore is the only place this rule will ever be consulted.
	def, ok := c.hookCatalog.Lookup(rule.Point)
	if !ok {
		return fmt.Errorf("ratelimitcatalog: rule %q targets undeclared hook point %q", rule.Name, rule.Point)
	}
	if def.Phase != types.BeforeHookPhase {
		return fmt.Errorf("ratelimitcatalog: rule %q targets point %q (phase %q) - rate-limit rules may only target Before-phase points", rule.Name, rule.Point, def.Phase)
	}

	c.names[rule.Name] = true
	c.rules[rule.Point] = append(c.rules[rule.Point], rule)
	return nil
}

func (c *DefaultRateLimitCatalog) RulesForHook(point types.HookPoint) []types.HookRateLimitRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rules[point] // safe to return directly post-boot
}

func (c *DefaultRateLimitCatalog) DeclareRouteRateLimitRule(rule types.RouteRateLimitRule) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.frozen {
		return errors.New("ratelimitcatalog: cannot DeclareRouteRateLimitRule after boot has completed")
	}

	if rule.Name == "" {
		return errors.New("ratelimitcatalog: route rule must have a Name")
	}
	if rule.Owner == "" {
		return fmt.Errorf("ratelimitcatalog: route rule %q missing Owner", rule.Name)
	}
	if c.names[rule.Name] {
		return fmt.Errorf("ratelimitcatalog: rule name %q already declared", rule.Name)
	}
	if !rule.Disabled {
		if err := checkRateLimitRule(rule.Name, rule.Action, rule.Algorithm, rule.Limiter, rule.Limit); err != nil {
			return err
		}
	}
	if rule.Path == "" {
		return fmt.Errorf("ratelimitcatalog: route rule %q missing Path", rule.Name)
	}
	if rule.Method == "" {
		rule.Method = "*"
	}

	c.names[rule.Name] = true
	c.routeRules = append(c.routeRules, rule)
	return nil
}

func (c *DefaultRateLimitCatalog) RulesForRoute() []types.RouteRateLimitRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.routeRules // safe to hand out directly post-freeze
}

func (c *DefaultRateLimitCatalog) Freeze() { c.mu.Lock(); c.frozen = true; c.mu.Unlock() }

var _ types.RateLimitCatalog = (*DefaultRateLimitCatalog)(nil)
