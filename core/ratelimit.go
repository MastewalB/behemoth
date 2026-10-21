package core

import (
	"context"
	"fmt"
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

	// Limits replaces the Limit of the rules it names, route and hook
	// rules alike, core's and the plugins'. A rule keeps its key, its
	// algorithm and its point; only the numbers change. Boot fails on a
	// name no rule has, and on a Limit without a positive Max and Window.
	Limits map[string]Limit
	// Disabled names rules that are not checked. A disabled route rule
	// leaves its routes without a limit, as a rule declared with Disabled
	// does. Boot fails on a name no rule has.
	Disabled []string
}

// RateLimitRule is a rule that a transport applies itself, such as an HTTP
// route rule (httpapi.RouteRateLimitRule): what the rate limiter counts with, under
// the name RateLimitConfig changes it by. The transport decides which calls
// the rule applies to and what each is counted per, and asks
// RateLimiter.CheckRule. It is declared with RateLimitCatalog.DeclareRule.
type RateLimitRule struct {
	Name      string
	Limit     Limit
	Algorithm RateLimitAlgorithm // empty means AlgorithmFixedWindow
	// Limiter, if set, is used instead of the one Boot builds for Algorithm
	// (see httpapi.RouteRateLimitRule).
	Limiter    Limiter
	Action     RateLimitAction // empty means ActionReject; ActionLockout is rejected at declaration (not built)
	LockoutFor time.Duration   // reserved for ActionLockout; not read
	// Disabled declares a rule that counts nothing: a transport's rule that
	// exempts some calls from a broader one, such as a route rule for one
	// path under a rule for a whole prefix. CheckRule lets every call
	// through, and the rule needs no Limit.
	Disabled bool
	Owner    string // set by the catalog the declarer receives
}

type HookRateLimitRule struct {
	Name  string
	Point HookPoint // which hook point this rule evaluates against
	// KeyFunc returns what the rule counts per, and whether the rule applies
	// to this call. It gets the HookContext and not the payload: it keys on
	// what the firing site published in hctx.Values before the dispatch (the
	// email of a sign-in, the kind and subject of a token issue), and on the
	// caller (hctx.Caller()), whose address the transport resolved.
	// docs/api/hooks.md lists the published values.
	//
	// When it returns false the rule is skipped for the call and nothing is
	// counted: a rule per client address has nothing to count for a call
	// from a CLI. A key returned with true is counted as it is, so "" is one
	// count shared by every caller. KeyByValues builds a KeyFunc from
	// Values entries, and KeyByClientIP from the caller's address.
	KeyFunc    func(hctx *HookContext) (key string, ok bool)
	Limit      Limit
	Algorithm  RateLimitAlgorithm // which strategy this rule uses; empty means AlgorithmFixedWindow
	Limiter    Limiter            // optional: the rule's own limiter, used instead of Algorithm's (see httpapi.RouteRateLimitRule)
	Action     RateLimitAction
	LockoutFor time.Duration // reserved for ActionLockout, which the catalog rejects (not built); not read

	Owner string // plugin name; same ownership discipline as HookPointDef/TokenKindDef
}

// KeyByClientIP returns a HookRateLimitRule.KeyFunc that keys on the
// caller's address (hctx.Caller().Peer().IPAddress), which the transport
// resolved with the router's proxy settings, followed by the Values entries
// under keys as KeyByValues joins them. The rule does not apply to a call
// whose caller has no address, such as code in the process, nor to one in
// which an entry under keys is missing or empty.
//
// It is how a limit per client address counts every call of a flow, over
// HTTP or another transport, where a route rule counts the requests to one
// path.
func KeyByClientIP(keys ...string) func(hctx *HookContext) (string, bool) {
	byValues := KeyByValues(keys...)
	return func(hctx *HookContext) (string, bool) {
		ip := hctx.Caller().Peer().IPAddress
		if ip == "" {
			return "", false
		}
		if len(keys) == 0 {
			return ip, true
		}
		values, ok := byValues(hctx)
		if !ok {
			return "", false
		}
		return ip + "|" + values, true
	}
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

// RateLimitCatalog holds the declared rate-limit rules: hook rules by the
// point they guard, and the rules transports apply themselves, such as
// httpapi's route rules. Plugins declare into it at Prepare, and the rate
// limiter reads it.
type RateLimitCatalog interface {
	DeclareHookRateLimitRule(rule HookRateLimitRule) error
	RulesForHook(point HookPoint) []HookRateLimitRule

	// DeclareRule declares a rule that a transport applies itself. Its name
	// is unique among every rule, hook rules included. Prepare declares one
	// for each route rule a plugin returns (httpapi.RouteRulesPlugin).
	DeclareRule(rule RateLimitRule) error
	// Rule returns the rule declared under name with DeclareRule.
	Rule(name string) (RateLimitRule, bool)

	// HasRule reports whether a rule of any kind is declared under name.
	// Boot checks RateLimitConfig's names with it.
	HasRule(name string) bool
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

// RateLimiter checks the declared rules. AuthContext.RateLimiter is one.
type RateLimiter interface {
	// CheckHookLimit counts one call of point against every hook rule
	// declared on it. The dispatcher calls it before the point's before
	// chain.
	CheckHookLimit(ctx context.Context, point HookPoint, hctx *HookContext) error

	// CheckRule counts one call against the rule declared under name with
	// RateLimitCatalog.DeclareRule. key is what the transport counts the
	// call per, such as the client's address. ip is the client's address,
	// which the audit event of a refusal records; "" when the transport
	// knows none. The rule's limit is the one RateLimitConfig.Limits sets
	// for its name, if any, and a refusal is the same error as a hook
	// rule's. A rule declared Disabled, or named in RateLimitConfig.Disabled,
	// lets every call through. An undeclared name is a configuration error.
	CheckRule(ctx context.Context, name, key, ip string) error
}
