package ratelimit

import (
	"context"
	"errors"
	"github.com/MastewalB/behemoth/dispatch"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/telemetry/telemetrytest"
	"github.com/MastewalB/behemoth/types"
)

// A rule names its algorithm, or brings a Limiter of its own. The catalog
// rejects a name nothing builds and a limit that can't be counted, and the
// rate limiter resolves the name to the Limiter Boot built.
func TestRateLimitRulesNameTheirAlgorithm(t *testing.T) {
	keyFunc := func(*http.Request, string) string { return "k" }
	declare := func(rule types.RouteRateLimitRule) error {
		rule.Method, rule.Path, rule.KeyFunc, rule.Owner = http.MethodPost, "/x", keyFunc, "test"
		return NewRateLimitCatalog(dispatch.NewDefaultHookCatalog()).DeclareRouteRateLimitRule(rule)
	}
	limit := types.Limit{Max: 5, Window: time.Minute}
	for name, tc := range map[string]struct {
		rule types.RouteRateLimitRule
		ok   bool
	}{
		"the default algorithm":         {types.RouteRateLimitRule{Name: "a", Limit: limit}, true},
		"fixed window by name":          {types.RouteRateLimitRule{Name: "b", Limit: limit, Algorithm: types.AlgorithmFixedWindow}, true},
		"an unknown algorithm":          {types.RouteRateLimitRule{Name: "c", Limit: limit, Algorithm: "token_bucket"}, false},
		"no limit":                      {types.RouteRateLimitRule{Name: "d"}, false},
		"no window":                     {types.RouteRateLimitRule{Name: "e", Limit: types.Limit{Max: 5}}, false},
		"its own limiter, any limit":    {types.RouteRateLimitRule{Name: "f", Limiter: fixedLimiter{allowed: true}}, true},
		"disabled rules are not judged": {types.RouteRateLimitRule{Name: "g", Disabled: true}, true},
		"reject by name":                {types.RouteRateLimitRule{Name: "h", Limit: limit, Action: types.ActionReject}, true},
		"lockout is not built":          {types.RouteRateLimitRule{Name: "i", Limit: limit, Action: types.ActionLockout, LockoutFor: time.Hour}, false},
		"lockout with its own limiter":  {types.RouteRateLimitRule{Name: "j", Limiter: fixedLimiter{allowed: true}, Action: types.ActionLockout}, false},
		"an unknown action":             {types.RouteRateLimitRule{Name: "k", Limit: limit, Action: "ban"}, false},
	} {
		if err := declare(tc.rule); (err == nil) != tc.ok {
			t.Errorf("%s: Declare = %v, want ok=%v", name, err, tc.ok)
		}
	}

	// A hook rule goes through the same check.
	hookCatalog := dispatch.NewDefaultHookCatalog()
	if err := hookCatalog.Declare(types.HookPointDef{Point: "test.thing.before", Owner: "test", Phase: types.BeforeHookPhase}); err != nil {
		t.Fatal(err)
	}
	err := NewRateLimitCatalog(hookCatalog).DeclareHookRateLimitRule(types.HookRateLimitRule{
		Name: "l", Point: "test.thing.before", KeyFunc: types.KeyByValues("email"), Limit: limit,
		Action: types.ActionLockout, LockoutFor: time.Hour, Owner: "test",
	})
	if err == nil || !strings.Contains(err.Error(), "ActionLockout") {
		t.Errorf("a hook rule with ActionLockout: Declare = %v, want an error naming the action", err)
	}

	built, own := fixedLimiter{allowed: true}, fixedLimiter{allowed: false}
	rl := &DefaultRateLimiter{limiters: map[types.RateLimitAlgorithm]types.Limiter{types.AlgorithmFixedWindow: built}}
	if got, err := rl.limiterFor("r", "", nil); err != nil || got != types.Limiter(built) {
		t.Errorf("an empty algorithm resolved to (%v, %v), want the fixed window", got, err)
	}
	if got, err := rl.limiterFor("r", types.AlgorithmFixedWindow, own); err != nil || got != types.Limiter(own) {
		t.Errorf("a rule's own limiter resolved to (%v, %v), want its own", got, err)
	}
	if _, err := rl.limiterFor("r", "token_bucket", nil); !errs.IsCategory(err, errs.CategoryConfiguration) {
		t.Errorf("an algorithm with no limiter returned %v, want a configuration error", err)
	}
}

// keyRecorder is a Limiter that allows every attempt and keeps the keys it
// was asked about.
type keyRecorder struct{ keys *[]string }

func (l keyRecorder) Allow(_ context.Context, key string, _ types.Limit) (bool, time.Duration, error) {
	*l.keys = append(*l.keys, key)
	return true, 0, nil
}

// A hook rule whose KeyFunc returns false is skipped for the call: nothing
// is counted for it, and the point's other rules are still checked. An empty
// key returned with true is counted like any other.
func TestHookRuleIsSkippedWhenItDoesNotApply(t *testing.T) {
	const point = types.HookPoint("test.thing.before")
	hookCatalog := dispatch.NewDefaultHookCatalog()
	if err := hookCatalog.Declare(types.HookPointDef{Point: point, Owner: "test", Phase: types.BeforeHookPhase}); err != nil {
		t.Fatal(err)
	}
	var keys []string
	catalog := NewRateLimitCatalog(hookCatalog)
	for name, keyFunc := range map[string]func(*types.HookContext) (string, bool){
		"per.email": types.KeyByValues("email"),
		"global":    func(*types.HookContext) (string, bool) { return "", true },
	} {
		if err := catalog.DeclareHookRateLimitRule(types.HookRateLimitRule{
			Name: name, Point: point, KeyFunc: keyFunc, Limiter: keyRecorder{&keys}, Owner: "test",
		}); err != nil {
			t.Fatal(err)
		}
	}
	tel, rec := telemetrytest.New()
	rl := &DefaultRateLimiter{catalog: catalog, tel: tel}
	ctx := context.Background()

	for _, values := range []behemoth.M{{}, {"email": ""}, {"email": "ada@example.com"}} {
		if err := rl.CheckHookLimit(ctx, point, &types.HookContext{Ctx: ctx, Values: values}); err != nil {
			t.Fatal(err)
		}
	}

	slices.Sort(keys)
	if want := []string{"global:", "global:", "global:", "per.email:ada@example.com"}; !slices.Equal(keys, want) {
		t.Errorf("keys counted = %q, want %q", keys, want)
	}
	for rule, want := range map[string]int64{"per.email": 2, "global": 0} {
		if n := rec.Metrics.Count(telemetry.MetricRateLimitChecks, behemoth.M{telemetry.AttrRule: rule, telemetry.AttrResult: "skipped"}); n != want {
			t.Errorf("skipped checks of %q = %d, want %d", rule, n, want)
		}
	}
}

// fixedLimiter answers every check the same way.
type fixedLimiter struct {
	allowed bool
	err     error
}

func (l fixedLimiter) Allow(context.Context, string, types.Limit) (bool, time.Duration, error) {
	return l.allowed, time.Second, l.err
}

// Each evaluated rule is counted once with how it ended, and a rejection is
// also an audit event with the outcome "denied".
func TestRateLimiterMetrics(t *testing.T) {
	tel, rec := telemetrytest.New()
	rl := &DefaultRateLimiter{tel: tel}
	ctx := context.Background()
	check := func(l types.Limiter) error {
		return rl.evaluate(ctx, "signin", "signin:203.0.113.7", "203.0.113.7", l, types.Limit{}, "", 0)
	}

	if err := check(fixedLimiter{allowed: true}); err != nil {
		t.Fatal(err)
	}
	if err := check(fixedLimiter{allowed: false}); !errs.IsCategory(err, errs.CategoryRateLimited) {
		t.Fatalf("a rejected check returned %v", err)
	}
	if err := check(fixedLimiter{err: errors.New("redis down")}); err != nil {
		t.Fatalf("a store failure with fail-open returned %v", err)
	}

	for result, want := range map[string]int64{"allowed": 1, "limited": 1, "error": 1} {
		if n := rec.Metrics.Count(telemetry.MetricRateLimitChecks, behemoth.M{telemetry.AttrRule: "signin", telemetry.AttrResult: result}); n != want {
			t.Errorf("checks with result %q = %d, want %d", result, n, want)
		}
	}
	events := rec.Audit.OfType(telemetry.AuditRateLimitExceeded)
	if len(events) != 1 || events[0].Outcome != telemetry.OutcomeDenied || events[0].IPAddress != "203.0.113.7" {
		t.Errorf("audit events = %+v, want one denied event with the address", events)
	}
}
