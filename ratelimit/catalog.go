package ratelimit

import (
	"errors"
	"fmt"
	"sync"

	"github.com/MastewalB/behemoth/core"
)

type DefaultRateLimitCatalog struct {
	frozen      bool
	mu          sync.RWMutex
	hookCatalog core.HookCatalog // read-only reference, for cross-validating Point at Declare time

	rules      map[core.HookPoint][]core.HookRateLimitRule
	routeRules []core.RouteRateLimitRule
	declared   map[string]core.RateLimitRule // the rules of DeclareRule, by name
	names      map[string]bool
}

func NewRateLimitCatalog(hooks core.HookCatalog) *DefaultRateLimitCatalog {
	return &DefaultRateLimitCatalog{
		hookCatalog: hooks,
		rules:       map[core.HookPoint][]core.HookRateLimitRule{},
		declared:    map[string]core.RateLimitRule{},
		names:       map[string]bool{},
	}
}

func (c *DefaultRateLimitCatalog) DeclareHookRateLimitRule(rule core.HookRateLimitRule) error {
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
	if def.Phase != core.BeforeHookPhase {
		return fmt.Errorf("ratelimitcatalog: rule %q targets point %q (phase %q) - rate-limit rules may only target Before-phase points", rule.Name, rule.Point, def.Phase)
	}

	c.names[rule.Name] = true
	c.rules[rule.Point] = append(c.rules[rule.Point], rule)
	return nil
}

func (c *DefaultRateLimitCatalog) RulesForHook(point core.HookPoint) []core.HookRateLimitRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rules[point] // safe to return directly post-boot
}

// DeclareRouteRateLimitRule implements [core.RateLimitCatalog]. It declares
// the rule's counting part under its name, as DeclareRule does, and keeps
// the rule for RulesForRoute.
func (c *DefaultRateLimitCatalog) DeclareRouteRateLimitRule(rule core.RouteRateLimitRule) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if rule.Path == "" {
		return fmt.Errorf("ratelimitcatalog: route rule %q missing Path", rule.Name)
	}
	if rule.Method == "" {
		rule.Method = "*"
	}
	if err := c.declareRule(rule.RateLimitRule()); err != nil {
		return err
	}
	c.routeRules = append(c.routeRules, rule)
	return nil
}

// DeclareRule implements [core.RateLimitCatalog].
func (c *DefaultRateLimitCatalog) DeclareRule(rule core.RateLimitRule) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.declareRule(rule)
}

// declareRule checks and records rule. The caller holds c.mu.
func (c *DefaultRateLimitCatalog) declareRule(rule core.RateLimitRule) error {
	if c.frozen {
		return errors.New("ratelimitcatalog: cannot declare a rule after boot has completed")
	}
	if rule.Name == "" {
		return errors.New("ratelimitcatalog: rule must have a Name")
	}
	if rule.Owner == "" {
		return fmt.Errorf("ratelimitcatalog: rule %q missing Owner", rule.Name)
	}
	if c.names[rule.Name] {
		return fmt.Errorf("ratelimitcatalog: rule name %q already declared", rule.Name)
	}
	if !rule.Disabled {
		if err := checkRateLimitRule(rule.Name, rule.Action, rule.Algorithm, rule.Limiter, rule.Limit); err != nil {
			return err
		}
	}
	c.names[rule.Name] = true
	c.declared[rule.Name] = rule
	return nil
}

// Rule implements [core.RateLimitCatalog].
func (c *DefaultRateLimitCatalog) Rule(name string) (core.RateLimitRule, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rule, ok := c.declared[name]
	return rule, ok
}

func (c *DefaultRateLimitCatalog) RulesForRoute() []core.RouteRateLimitRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.routeRules // safe to hand out directly post-freeze
}

// HasRule implements [core.RateLimitCatalog].
func (c *DefaultRateLimitCatalog) HasRule(name string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.names[name]
}

func (c *DefaultRateLimitCatalog) Freeze() { c.mu.Lock(); c.frozen = true; c.mu.Unlock() }

var _ core.RateLimitCatalog = (*DefaultRateLimitCatalog)(nil)
