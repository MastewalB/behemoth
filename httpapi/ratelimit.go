package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-behemoth/behemoth/core"
)

// RouteRateLimitRule limits the requests to the routes whose method and path
// it matches. Of the rules that match a route, the most specific one
// applies (BestRouteMatch), where every hook rule of a point applies
// (core.HookRateLimitRule). A plugin returns its route rules from
// RouteRulesPlugin, and Prepare declares them (DeclareRouteRules).
//
// Prefer a hook rule, which holds however a flow is reached: a route rule
// suits what is about HTTP itself, or a flow with no before point.
type RouteRateLimitRule struct {
	Name   string
	Method string // exact verb, or "*" to match any method
	Path   string // canonical pattern: literal segments, "*" (exactly one segment), "**" (trailing, zero or more, must be the last segment)

	KeyFunc func(r *http.Request, ip string) string
	Limit   core.Limit
	// Algorithm names the strategy. Empty means AlgorithmFixedWindow.
	Algorithm core.RateLimitAlgorithm
	// Limiter, if set, is used instead of the one Boot builds for Algorithm.
	// It is for a strategy core does not have; it has to bring its own
	// storage, since it exists before Boot.
	Limiter    core.Limiter
	Action     core.RateLimitAction // empty means ActionReject; ActionLockout is rejected at declaration (not built)
	LockoutFor time.Duration        // reserved for ActionLockout; not read

	Disabled bool // true = explicitly exempt this pattern from broader rule that would otherwise match
	Owner    string
}

// RateLimitRule returns the part of r the rate limiter counts with, which
// DeclareRouteRules declares under r's name.
func (r RouteRateLimitRule) RateLimitRule() core.RateLimitRule {
	return core.RateLimitRule{
		Name: r.Name, Limit: r.Limit, Algorithm: r.Algorithm, Limiter: r.Limiter,
		Action: r.Action, LockoutFor: r.LockoutFor, Disabled: r.Disabled, Owner: r.Owner,
	}
}

// DeclareRouteRules declares rules, owned by owner, in catalog: the counting
// part of each (RateLimitRule), under its name, so that names stay unique
// across hook and route rules and RateLimitConfig changes either kind by
// name. It returns the rules as the router applies them
// (Router.ApplyRateLimiting): owned by owner, and with an empty Method
// matching any method. A rule without a Path, or without a KeyFunc unless
// it is Disabled, is an error, and so is anything catalog refuses.
//
// Prepare calls it for every plugin that implements RouteRulesPlugin.
func DeclareRouteRules(catalog core.RateLimitCatalog, owner string, rules []RouteRateLimitRule) ([]RouteRateLimitRule, error) {
	declared := make([]RouteRateLimitRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Path == "" {
			return nil, fmt.Errorf("ratelimit: route rule %q missing Path", rule.Name)
		}
		if rule.KeyFunc == nil && !rule.Disabled {
			return nil, fmt.Errorf("ratelimit: route rule %q missing KeyFunc", rule.Name)
		}
		if rule.Method == "" {
			rule.Method = "*"
		}
		rule.Owner = owner
		if err := catalog.DeclareRule(rule.RateLimitRule()); err != nil {
			return nil, err
		}
		declared = append(declared, rule)
	}
	return declared, nil
}

// SplitPath returns the segments of p, without empty ones at its ends.
func SplitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}

	return strings.Split(p, "/")
}

// MatchesPath reports whether path matches pattern, a route rule's Path:
// "*" matches one segment, and a last segment "**" any number of segments,
// or none.
func MatchesPath(pattern, path string) bool {
	pSegments, rSegments := SplitPath(pattern), SplitPath(path)
	for i, ps := range pSegments {
		if ps == "**" {
			return true // matches regardless of what remains, including nothing
		}
		if i >= len(rSegments) {
			return false
		}
		if ps == "*" {
			continue
		}
		if ps != rSegments[i] {
			return false
		}
	}

	return len(pSegments) == len(rSegments)
}

// MatchesMethod reports whether method matches a route rule's Method: the
// same verb in any case, or "*".
func MatchesMethod(ruleMethod, method string) bool {
	return ruleMethod == "*" || strings.EqualFold(ruleMethod, method)
}

// specificity produces a comparable score so that when multiple declared
// rules match the same request, the most deliberately-targeted one wins;
//
//	a specific custom Rule overrides the broader default for that path, rather than both
//
// applying and stacking. Compared as a tuple, most significant first:
//  1. exact method match beats "*" (a method-specific rule is clearly more deliberate)
//  2. more literal path segments wins (fewer wildcards = more specific)
//  3. presence of "**" loses to any pattern without one (trailing wildcard is the least specific construct)
//  4. longer pattern (more segments) wins as the final tiebreak
type specificity struct {
	exactMethod   bool
	literalCount  int
	hasDoubleStar bool
	segmentCount  int
}

func scoreOf(rule RouteRateLimitRule) specificity {
	sgmts := SplitPath(rule.Path)
	s := specificity{exactMethod: rule.Method != "*", segmentCount: len(sgmts)}
	for _, sg := range sgmts {
		switch sg {
		case "**":
			s.hasDoubleStar = true
		case "*":
			// wildcard segment: contributes to segmentCount only, not literalCount
		default:
			s.literalCount++
		}
	}
	return s
}

// moreSpecific reports whether a should be preferred over b when both match.
func moreSpecific(a, b specificity) bool {
	if a.exactMethod != b.exactMethod {
		return a.exactMethod
	}
	if a.literalCount != b.literalCount {
		return a.literalCount > b.literalCount
	}

	if a.hasDoubleStar != b.hasDoubleStar {
		return !a.hasDoubleStar
	}
	return a.segmentCount > b.segmentCount
}

// BestRouteMatch returns the most specific of rules that match method and
// path (see specificity), and false when none does.
func BestRouteMatch(rules []RouteRateLimitRule, method, path string) (RouteRateLimitRule, bool) {
	var bestRule RouteRateLimitRule
	var bestScore specificity
	found := false

	for _, r := range rules {
		if !MatchesMethod(r.Method, method) || !MatchesPath(r.Path, path) {
			continue
		}
		score := scoreOf(r)
		if !found || moreSpecific(score, bestScore) {
			bestRule, bestScore, found = r, score, true
		}
	}
	return bestRule, found
}
