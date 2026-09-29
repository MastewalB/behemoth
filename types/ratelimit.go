package types

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// Limiter is one rate-limiting strategy. Multiple concrete algorithms
// implement it and a rule picks which one it wants based on the desired behavior
// (bursty API traffic vs. strict auth-attempt counting)
type Limiter interface {
	// Allow atomically checks-and-records one attempt against key.
	// Returns allowed, and if not, a RetryAfter hint.
	Allow(ctx context.Context, key string, limit Limit) (allowed bool, retryAfter time.Duration, err error)
}

type Limit struct {
	Max    int64
	Window time.Duration
}

type RateLimitAction string
type FailureMode string

const (
	ActionReject  RateLimitAction = "reject"  // hard block, return immediately
	ActionLockout RateLimitAction = "lockout" // block for a fixed penalty duration, independent of window reset
)

const (
	FailOpen   FailureMode = "fail_open"   // store unreachable -> log and allow the request
	FailClosed FailureMode = "fail_closed" // store unreachable -> reject the request
)

type RateLimitConfig struct {
	FailureMode FailureMode // default: FailOpen
}

type RouteRateLimitRule struct {
	Name   string
	Method string // exact verb, or "*" to match any method
	Path   string // canonical pattern: literal segments, "*" (exactly one segment), "**" (trailing, zero or more, must be the last segment)

	KeyFunc    func(r *http.Request, ip string) string
	Limit      Limit
	Algorithm  Limiter
	Action     RateLimitAction
	LockoutFor time.Duration

	Disabled bool // true = explicitly exempt this pattern from broader rule that would otherwise match
	Owner    string
}

type HookRateLimitRule struct {
	Name       string
	Point      HookPoint                      // which hook point this rule evaluates against
	KeyFunc    func(hctx *HookContext) string // e.g. by IP, by email, by userID+IP composite
	Limit      Limit
	Algorithm  Limiter // which strategy this rule uses
	Action     RateLimitAction
	LockoutFor time.Duration // only relevant if Action == ActionLockout

	Owner string // plugin name; same ownership discipline as HookPointDef/TokenKindDef
}

type RateLimitCatalog interface {
	DeclareHookRateLimitRule(rule HookRateLimitRule) error
	RulesForHook(point HookPoint) []HookRateLimitRule

	DeclareRouteRateLimitRule(rule RouteRateLimitRule) error
	RulesForRoute() []RouteRateLimitRule
}

func SplitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}

	return strings.Split(p, "/")
}

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

// AtomicIncrementer is an optional capability a KeyValueStorage backend may
// implement (Redis's INCR/EXPIRE natively support this). Rate limiting checks
// for it via assertion.
type AtomicIncrementer interface {
	Increment(ctx context.Context, key string, ttl time.Duration) (count int64, err error)
}

type RateLimiter interface {
	CheckHookLimit(ctx context.Context, point HookPoint, hctx *HookContext) error
	CheckRouteLimit(ctx context.Context, rule RouteRateLimitRule, r *http.Request, ipCfg *ClientIPConfig) error
}
