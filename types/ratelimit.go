package types

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// RateLimitAlgorithm names the strategy a rule counts with. A rule holds the
// name and not a Limiter because rules are declared at Prepare, before any
// database or key-value connection exists: Boot builds the Limiter of each
// algorithm once it has resolved where counters are kept.
type RateLimitAlgorithm string

// AlgorithmFixedWindow allows Limit.Max attempts per key in each window of
// Limit.Window. A window opens with the first attempt and the count starts
// again when it has passed. It is the default, and the only algorithm core
// builds.
//
// A client can use up one window at its end and the next at its start, so up
// to twice Max attempts can fall within one Window's length. A sliding
// window or a token bucket would not allow that; neither is built. Each needs
// more state per key than the one counter AtomicIncrementer keeps.
const AlgorithmFixedWindow RateLimitAlgorithm = "fixed_window"

// Limiter is one rate-limiting strategy: the implementation behind a
// RateLimitAlgorithm, or a rule's own (the rules' Limiter field).
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

	KeyFunc func(r *http.Request, ip string) string
	Limit   Limit
	// Algorithm names the strategy. Empty means AlgorithmFixedWindow.
	Algorithm RateLimitAlgorithm
	// Limiter, if set, is used instead of the one Boot builds for Algorithm.
	// It is for a strategy core does not have; it has to bring its own
	// storage, since it exists before Boot.
	Limiter    Limiter
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
	Algorithm  RateLimitAlgorithm // which strategy this rule uses; empty means AlgorithmFixedWindow
	Limiter    Limiter            // optional: the rule's own limiter, used instead of Algorithm's (see RouteRateLimitRule)
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

// AtomicIncrementer is a fixed-window counter: the storage behind
// AlgorithmFixedWindow. It is an optional capability of a KeyValueStorage
// (the Redis adapter has it), which Boot finds by type assertion; without
// one, counters are kept in the rate_limits table.
type AtomicIncrementer interface {
	// Increment counts one attempt against key, as one atomic step, and
	// returns the count in the current window and when that window ends.
	// The first attempt for a key opens a window of ttl; the first one
	// after it has ended opens the next, starting again at 1.
	//
	// resetAt is what a refused caller is told to wait for. It is a time
	// and not a duration so that it stays right however long the call took.
	Increment(ctx context.Context, key string, ttl time.Duration) (count int64, resetAt time.Time, err error)
}

type RateLimiter interface {
	CheckHookLimit(ctx context.Context, point HookPoint, hctx *HookContext) error
	CheckRouteLimit(ctx context.Context, rule RouteRateLimitRule, r *http.Request, ipCfg *ClientIPConfig) error
}
