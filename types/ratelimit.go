package types

import (
	"context"
	"fmt"
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

// RateLimitAction is what a rule does with an attempt over its limit. The
// empty value means ActionReject.
type RateLimitAction string
type FailureMode string

const (
	// ActionReject refuses the attempt until the rule's window ends.
	ActionReject RateLimitAction = "reject"
	// ActionLockout is to refuse the key for the rule's LockoutFor, whatever
	// the window does. It is not built: the rate-limit catalog rejects a
	// rule that asks for it, so no rule can rely on a lockout it would not
	// get. The value and LockoutFor are kept so that rules need no new
	// field once it is. docs/internal/ratelimit/rate_limiter.md has the
	// plan.
	ActionLockout RateLimitAction = "lockout"
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
	Action     RateLimitAction // empty means ActionReject; ActionLockout is rejected at declaration (not built)
	LockoutFor time.Duration   // reserved for ActionLockout; not read

	Disabled bool // true = explicitly exempt this pattern from broader rule that would otherwise match
	Owner    string
}

type HookRateLimitRule struct {
	Name  string
	Point HookPoint // which hook point this rule evaluates against
	// KeyFunc returns what the rule counts per, and whether the rule applies
	// to this call. It gets the HookContext and not the payload: it keys on
	// what the firing site published in hctx.Values before the dispatch (the
	// email of a sign-in, the kind and subject of a token issue), and on
	// hctx.Request, which is nil outside an HTTP request. docs/api/hooks.md
	// lists the published values.
	//
	// When it returns false the rule is skipped for the call and nothing is
	// counted: a rule per client address has nothing to count for a call
	// from a CLI. A key returned with true is counted as it is, so "" is one
	// count shared by every caller. KeyByValues builds a KeyFunc from
	// Values entries.
	KeyFunc    func(hctx *HookContext) (key string, ok bool)
	Limit      Limit
	Algorithm  RateLimitAlgorithm // which strategy this rule uses; empty means AlgorithmFixedWindow
	Limiter    Limiter            // optional: the rule's own limiter, used instead of Algorithm's (see RouteRateLimitRule)
	Action     RateLimitAction
	LockoutFor time.Duration // reserved for ActionLockout, which the catalog rejects (not built); not read

	Owner string // plugin name; same ownership discipline as HookPointDef/TokenKindDef
}

// KeyByValues returns a HookRateLimitRule.KeyFunc that keys on the entries
// of HookContext.Values under keys, joined with "|" in the order given. The
// rule does not apply to a call in which one of them is missing or empty.
// An entry that is not a string is formatted with fmt.Sprint.
func KeyByValues(keys ...string) func(hctx *HookContext) (string, bool) {
	return func(hctx *HookContext) (string, bool) {
		parts := make([]string, len(keys))
		for i, k := range keys {
			switch v := hctx.Values[k].(type) {
			case nil:
				return "", false
			case string:
				parts[i] = v
			default:
				parts[i] = fmt.Sprint(v)
			}
			if parts[i] == "" {
				return "", false
			}
		}
		return strings.Join(parts, "|"), true
	}
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
