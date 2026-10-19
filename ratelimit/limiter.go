package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/telemetry"
)

// dbCounterStore counts in the rate_limits table: the AtomicIncrementer used
// when no KeyValueStorage provides one.
type dbCounterStore struct{ store *store.Store }

func (s *dbCounterStore) Increment(ctx context.Context, key string, ttl time.Duration) (int64, time.Time, error) {
	return s.store.IncrementRateLimit(ctx, key, ttl)
}

// DefaultRateLimiter evaluates the declared rules. limiters holds the Limiter
// Boot built for each algorithm, over the counter storage it resolved
// (newLimiters); a rule's own Limiter takes its place.
type DefaultRateLimiter struct {
	catalog  core.RateLimitCatalog
	limiters map[core.RateLimitAlgorithm]core.Limiter
	cfg      core.RateLimitConfig
	tel      *telemetry.Telemetry
}

// NewDefaultRateLimiter returns the rate limiter of the rules in catalog. It
// counts attempts in kv when kv can count atomically, as the Redis adapter
// can, and in the rate_limits table through st otherwise.
func NewDefaultRateLimiter(catalog core.RateLimitCatalog, kv behemoth.KeyValueStorage, st *store.Store, cfg core.RateLimitConfig, tel *telemetry.Telemetry) (*DefaultRateLimiter, error) {
	counter, err := resolveRateLimitStore(kv, st)
	if err != nil {
		return nil, err
	}
	return &DefaultRateLimiter{catalog: catalog, limiters: newLimiters(counter), cfg: cfg, tel: telemetry.OrDefault(tel).Named("ratelimit")}, nil
}

// knownAlgorithms are the algorithms a rule may name; newLimiters builds a
// Limiter for each. The catalog rejects any other name at Prepare.
var knownAlgorithms = map[core.RateLimitAlgorithm]bool{core.AlgorithmFixedWindow: true}

// newLimiters builds the Limiter of every known algorithm over counter.
func newLimiters(counter core.AtomicIncrementer) map[core.RateLimitAlgorithm]core.Limiter {
	return map[core.RateLimitAlgorithm]core.Limiter{
		core.AlgorithmFixedWindow: NewFixedWindow(counter),
	}
}

// limiterFor returns the Limiter a rule is evaluated with: its own, or the
// one built for its algorithm, where an empty name means the fixed window.
func (rl *DefaultRateLimiter) limiterFor(rule string, algorithm core.RateLimitAlgorithm, own core.Limiter) (core.Limiter, error) {
	if own != nil {
		return own, nil
	}
	if algorithm == "" {
		algorithm = core.AlgorithmFixedWindow
	}
	if l, ok := rl.limiters[algorithm]; ok {
		return l, nil
	}
	return nil, errs.NewConfigurationError("RateLimiter", fmt.Sprintf("rule %q names the algorithm %q, which has no limiter", rule, algorithm), nil)
}

// checkRateLimitRule is what the catalog requires of a rule's strategy: an
// action that is built, and a known algorithm with a limit that can be
// counted, or a Limiter of its own, whose limit is its own business.
//
// ActionLockout is refused here, at Prepare, and not at request time: a rule
// that asked for a lockout would otherwise get an ordinary rejection and its
// author would not find out. The check comes before the rule's own Limiter
// is accepted, because the lockout is the rate limiter's to enforce, not the
// Limiter's.
func checkRateLimitRule(name string, action core.RateLimitAction, algorithm core.RateLimitAlgorithm, own core.Limiter, limit core.Limit) error {
	switch action {
	case "", core.ActionReject:
	case core.ActionLockout:
		return fmt.Errorf("ratelimit: rule %q uses ActionLockout, which is not built; use ActionReject", name)
	default:
		return fmt.Errorf("ratelimit: rule %q names an unknown Action %q", name, action)
	}
	if own != nil {
		return nil
	}
	if algorithm != "" && !knownAlgorithms[algorithm] {
		return fmt.Errorf("ratelimit: rule %q names an unknown Algorithm %q", name, algorithm)
	}
	if limit.Max <= 0 || limit.Window <= 0 {
		return fmt.Errorf("ratelimit: rule %q needs a Limit with a positive Max and Window", name)
	}
	return nil
}

func (rl *DefaultRateLimiter) CheckHookLimit(ctx context.Context, point core.HookPoint, hctx *core.HookContext) error {
	// UNLIKE RouteRule (single most-specific match wins), every declared
	// HookPointRule for a point is evaluated and must ALL pass — this is
	// deliberate, not an inconsistency: two independent plugins might each
	// have a legitimate, unrelated reason to bound the same point (core's
	// blunt sign-in lockout AND a plugin's separate suspicious-activity
	// counter), and both should apply simultaneously. Routes get
	// override/specificity semantics because a path is normally ONE
	// deliberately-configured policy; hook points get cumulative semantics
	// because multiple concerns legitimately compose there.

	rules := rl.catalog.RulesForHook(point)
	for _, rule := range rules {
		// A rule that has nothing to count this call per (no request for a
		// rule per address, no email on the sign-in) is skipped, not counted
		// under an empty key that every such caller would share.
		ruleKey, ok := rule.KeyFunc(hctx)
		if !ok {
			rl.countCheck(ctx, rule.Name, "skipped")
			continue
		}
		key := rule.Name + ":" + ruleKey
		limiter, err := rl.limiterFor(rule.Name, rule.Algorithm, rule.Limiter)
		if err != nil {
			return err
		}
		if err := rl.evaluate(ctx, rule.Name, key, "", limiter, rule.Limit, rule.Action, rule.LockoutFor); err != nil {
			return err
		}
	}

	return nil
}

func (rl *DefaultRateLimiter) CheckRouteLimit(ctx context.Context, rule core.RouteRateLimitRule, r *http.Request, ipCfg *core.ClientIPConfig) error {
	ip := core.ClientIP(r, ipCfg)
	key := rule.Name + ":" + rule.KeyFunc(r, ip)
	limiter, err := rl.limiterFor(rule.Name, rule.Algorithm, rule.Limiter)
	if err != nil {
		return err
	}
	if err := rl.evaluate(ctx, rule.Name, key, ip, limiter, rule.Limit, rule.Action, rule.LockoutFor); err != nil {
		return err // *errs.DomainError, CategoryRateLimited; ErrorMapper already maps this to 429 + Retry-After, no body parsing or session lookup ever ran
	}

	return nil
}

func (rl *DefaultRateLimiter) GetBestMatchforRoute(ctx context.Context, method, path string) (core.RouteRateLimitRule, bool) {
	rules := rl.catalog.RulesForRoute()
	return core.BestRouteMatch(rules, method, path)
}

// evaluate is the shared core: it asks the rule's limiter and turns a
// refusal into an audit event and a rate-limited error. Both the
// point-scoped path and route-scoped path call through here, so there is
// exactly one place that handles a refusal and a failing counter.
//
// Deferred: ActionLockout. No rule reaches here with it, because the catalog
// rejects it at declaration. When it is built it belongs here, around the
// call to the limiter: check a lockout key before counting and set it on the
// first refusal. action and lockoutFor are passed for that and not read.
func (rl *DefaultRateLimiter) evaluate(
	ctx context.Context,
	name, key string,
	ip string, // the client address, when the caller resolved one; recorded in the audit event
	algo core.Limiter,
	limit core.Limit,
	action core.RateLimitAction,
	lockoutFor time.Duration,
) error {
	var spanAttrs behemoth.M
	if rl.tel.TracingEnabled() {
		spanAttrs = behemoth.M{telemetry.AttrRule: name}
	}
	spanCtx, span := rl.tel.StartSpan(ctx, telemetry.SpanRateLimitCheck, spanAttrs)
	allowed, retryAfter, err := algo.Allow(spanCtx, key, limit)
	result := "allowed"
	switch {
	case err != nil:
		result = "error"
	case !allowed:
		result = "limited"
	}
	if rl.tel.TracingEnabled() {
		span.SetAttributes(behemoth.M{telemetry.AttrResult: result})
	}
	telemetry.FinishSpan(span, err)
	rl.countCheck(ctx, name, result)
	if err != nil {
		return rl.handleStoreFailure(ctx, name, err)
	}

	if !allowed {
		if rl.tel != nil {
			rl.tel.RecordAudit(ctx, telemetry.AuditEvent{
				Type: telemetry.AuditRateLimitExceeded, Outcome: telemetry.OutcomeDenied,
				IPAddress: ip, Metadata: behemoth.M{"rule": name, "key": key},
			})
		}
		return errs.NewRateLimited(name, name, retryAfter)
	}

	return nil
}

// countCheck counts one evaluation of rule: "allowed", "limited", "error"
// when the counter store could not be reached (what happens to the request
// then is RateLimitConfig.FailureMode's decision), or "skipped" when a hook
// rule's KeyFunc said the rule does not apply to the call.
func (rl *DefaultRateLimiter) countCheck(ctx context.Context, rule, result string) {
	if rl.tel.MetricsEnabled() {
		rl.tel.Count(ctx, telemetry.MetricRateLimitChecks, behemoth.M{telemetry.AttrRule: rule, telemetry.AttrResult: result})
	}
}

func (rl *DefaultRateLimiter) handleStoreFailure(ctx context.Context, rule string, err error) error {
	if rl.tel != nil {
		rl.tel.Logger.Warn(ctx, "rate limit store unavailable", telemetry.ErrorFields(err, behemoth.M{"rule": rule}))
	}
	if rl.cfg.FailureMode == core.FailClosed {
		return errs.NewRateLimited(rule, rule, 0)
	}
	return nil // FailOpen request proceeds
}

// resolveRateLimitStore picks where counters are kept: the key-value storage
// when it can count atomically (the Redis adapter), otherwise the
// rate_limits table.
func resolveRateLimitStore(kv behemoth.KeyValueStorage, st *store.Store) (core.AtomicIncrementer, error) {
	if kv != nil {
		if inc, ok := kv.(core.AtomicIncrementer); ok {
			return inc, nil
		}
	}
	return &dbCounterStore{store: st}, nil
}

var _ core.RateLimiter = (*DefaultRateLimiter)(nil)
