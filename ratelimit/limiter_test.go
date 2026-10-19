package ratelimit

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/dispatch"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/telemetry/telemetrytest"
)

// A rule names its algorithm, or brings a Limiter of its own. The catalog
// rejects a name nothing builds and a limit that can't be counted, and the
// rate limiter resolves the name to the Limiter Boot built.
func TestRateLimitRulesNameTheirAlgorithm(t *testing.T) {
	keyFunc := func(*http.Request, string) string { return "k" }
	declare := func(rule core.RouteRateLimitRule) error {
		rule.Method, rule.Path, rule.KeyFunc, rule.Owner = http.MethodPost, "/x", keyFunc, "test"
		return NewRateLimitCatalog(dispatch.NewDefaultHookCatalog()).DeclareRouteRateLimitRule(rule)
	}
	limit := core.Limit{Max: 5, Window: time.Minute}
	for name, tc := range map[string]struct {
		rule core.RouteRateLimitRule
		ok   bool
	}{
		"the default algorithm":         {core.RouteRateLimitRule{Name: "a", Limit: limit}, true},
		"fixed window by name":          {core.RouteRateLimitRule{Name: "b", Limit: limit, Algorithm: core.AlgorithmFixedWindow}, true},
		"an unknown algorithm":          {core.RouteRateLimitRule{Name: "c", Limit: limit, Algorithm: "token_bucket"}, false},
		"no limit":                      {core.RouteRateLimitRule{Name: "d"}, false},
		"no window":                     {core.RouteRateLimitRule{Name: "e", Limit: core.Limit{Max: 5}}, false},
		"its own limiter, any limit":    {core.RouteRateLimitRule{Name: "f", Limiter: fixedLimiter{allowed: true}}, true},
		"disabled rules are not judged": {core.RouteRateLimitRule{Name: "g", Disabled: true}, true},
		"reject by name":                {core.RouteRateLimitRule{Name: "h", Limit: limit, Action: core.ActionReject}, true},
		"lockout is not built":          {core.RouteRateLimitRule{Name: "i", Limit: limit, Action: core.ActionLockout, LockoutFor: time.Hour}, false},
		"lockout with its own limiter":  {core.RouteRateLimitRule{Name: "j", Limiter: fixedLimiter{allowed: true}, Action: core.ActionLockout}, false},
		"an unknown action":             {core.RouteRateLimitRule{Name: "k", Limit: limit, Action: "ban"}, false},
	} {
		if err := declare(tc.rule); (err == nil) != tc.ok {
			t.Errorf("%s: Declare = %v, want ok=%v", name, err, tc.ok)
		}
	}

	// A hook rule goes through the same check.
	hookCatalog := dispatch.NewDefaultHookCatalog()
	if err := hookCatalog.Declare(core.HookPointDef{Point: "test.thing.before", Owner: "test", Phase: core.BeforeHookPhase}); err != nil {
		t.Fatal(err)
	}
	err := NewRateLimitCatalog(hookCatalog).DeclareHookRateLimitRule(core.HookRateLimitRule{
		Name: "l", Point: "test.thing.before", KeyFunc: core.KeyByValues("email"), Limit: limit,
		Action: core.ActionLockout, LockoutFor: time.Hour, Owner: "test",
	})
	if err == nil || !strings.Contains(err.Error(), "ActionLockout") {
		t.Errorf("a hook rule with ActionLockout: Declare = %v, want an error naming the action", err)
	}

	built, own := fixedLimiter{allowed: true}, fixedLimiter{allowed: false}
	rl := &DefaultRateLimiter{limiters: map[core.RateLimitAlgorithm]core.Limiter{core.AlgorithmFixedWindow: built}}
	if got, err := rl.limiterFor("r", "", nil); err != nil || got != core.Limiter(built) {
		t.Errorf("an empty algorithm resolved to (%v, %v), want the fixed window", got, err)
	}
	if got, err := rl.limiterFor("r", core.AlgorithmFixedWindow, own); err != nil || got != core.Limiter(own) {
		t.Errorf("a rule's own limiter resolved to (%v, %v), want its own", got, err)
	}
	if _, err := rl.limiterFor("r", "token_bucket", nil); !errs.IsCategory(err, errs.CategoryConfiguration) {
		t.Errorf("an algorithm with no limiter returned %v, want a configuration error", err)
	}
}

// keyRecorder is a Limiter that allows every attempt and keeps the keys it
// was asked about.
type keyRecorder struct{ keys *[]string }

func (l keyRecorder) Allow(_ context.Context, key string, _ core.Limit) (bool, time.Duration, error) {
	*l.keys = append(*l.keys, key)
	return true, 0, nil
}

// A hook rule whose KeyFunc returns false is skipped for the call: nothing
// is counted for it, and the point's other rules are still checked. An empty
// key returned with true is counted like any other.
func TestHookRuleIsSkippedWhenItDoesNotApply(t *testing.T) {
	const point = core.HookPoint("test.thing.before")
	hookCatalog := dispatch.NewDefaultHookCatalog()
	if err := hookCatalog.Declare(core.HookPointDef{Point: point, Owner: "test", Phase: core.BeforeHookPhase}); err != nil {
		t.Fatal(err)
	}
	var keys []string
	catalog := NewRateLimitCatalog(hookCatalog)
	for name, keyFunc := range map[string]func(*core.HookContext) (string, bool){
		"per.email": core.KeyByValues("email"),
		"global":    func(*core.HookContext) (string, bool) { return "", true },
	} {
		if err := catalog.DeclareHookRateLimitRule(core.HookRateLimitRule{
			Name: name, Point: point, KeyFunc: keyFunc, Limiter: keyRecorder{&keys}, Owner: "test",
		}); err != nil {
			t.Fatal(err)
		}
	}
	tel, rec := telemetrytest.New()
	rl := &DefaultRateLimiter{catalog: catalog, tel: tel}
	ctx := context.Background()

	for _, values := range []behemoth.M{{}, {"email": ""}, {"email": "ada@example.com"}} {
		if err := rl.CheckHookLimit(ctx, point, &core.HookContext{Ctx: ctx, Values: values}); err != nil {
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

func (l fixedLimiter) Allow(context.Context, string, core.Limit) (bool, time.Duration, error) {
	return l.allowed, time.Second, l.err
}

// Each evaluated rule is counted once with how it ended, and a rejection is
// also an audit event with the outcome "denied".
func TestRateLimiterMetrics(t *testing.T) {
	tel, rec := telemetrytest.New()
	rl := &DefaultRateLimiter{tel: tel}
	ctx := context.Background()
	check := func(l core.Limiter) error {
		return rl.evaluate(ctx, "signin", "signin:203.0.113.7", "203.0.113.7", l, core.Limit{}, "", 0)
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

// limitRecorder allows every check and records the rule and limit of each.
type limitRecorder struct{ seen map[string]core.Limit }

func (l limitRecorder) Allow(_ context.Context, key string, limit core.Limit) (bool, time.Duration, error) {
	rule, _, _ := strings.Cut(key, ":")
	l.seen[rule] = limit
	return true, 0, nil
}

// RateLimitConfig.Limits replaces a rule's limit and Disabled turns a rule
// off, for hook and route rules alike. A name no rule has, or a limit that
// can't be counted, is a configuration error.
func TestRateLimitConfigChangesRulesByName(t *testing.T) {
	const point = core.HookPoint("test.thing.before")
	hookCatalog := dispatch.NewDefaultHookCatalog()
	if err := hookCatalog.Declare(core.HookPointDef{Point: point, Owner: "test", Phase: core.BeforeHookPhase}); err != nil {
		t.Fatal(err)
	}
	recorder := limitRecorder{seen: map[string]core.Limit{}}
	declared := core.Limit{Max: 10, Window: time.Minute}
	catalog := NewRateLimitCatalog(hookCatalog)
	for _, name := range []string{"hook.tuned", "hook.off", "hook.kept"} {
		if err := catalog.DeclareHookRateLimitRule(core.HookRateLimitRule{
			Name: name, Point: point, KeyFunc: core.KeyByValues(), Limit: declared, Limiter: recorder, Owner: "test",
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"route.tuned", "route.off"} {
		if err := catalog.DeclareRouteRateLimitRule(core.RouteRateLimitRule{
			Name: name, Method: http.MethodPost, Path: "/" + name, KeyFunc: func(*http.Request, string) string { return "" },
			Limit: declared, Limiter: recorder, Owner: "test",
		}); err != nil {
			t.Fatal(err)
		}
	}

	tuned := core.Limit{Max: 3, Window: time.Hour}
	cfg := core.RateLimitConfig{
		Limits:   map[string]core.Limit{"hook.tuned": tuned, "route.tuned": tuned},
		Disabled: []string{"hook.off", "route.off"},
	}
	rl, err := NewDefaultRateLimiter(catalog, nil, nil, cfg, core.AuditConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := rl.CheckHookLimit(ctx, point, &core.HookContext{Ctx: ctx}); err != nil {
		t.Fatal(err)
	}
	for _, rule := range catalog.RulesForRoute() {
		if err := rl.CheckRouteLimit(ctx, rule, httptest.NewRequest(http.MethodPost, rule.Path, nil), &core.ClientIPConfig{}); err != nil {
			t.Fatal(err)
		}
	}
	want := map[string]core.Limit{"hook.tuned": tuned, "hook.kept": declared, "route.tuned": tuned}
	if !maps.Equal(recorder.seen, want) {
		t.Errorf("checks made = %v, want %v: the tuned rules with their new limit, the disabled ones not at all", recorder.seen, want)
	}

	for name, bad := range map[string]core.RateLimitConfig{
		"a limit for no rule":      {Limits: map[string]core.Limit{"no.such.rule": tuned}},
		"a limit that can't count": {Limits: map[string]core.Limit{"hook.tuned": {Max: 0, Window: time.Minute}}},
		"disabling no rule":        {Disabled: []string{"no.such.rule"}},
	} {
		if _, err := NewDefaultRateLimiter(catalog, nil, nil, bad, core.AuditConfig{}, nil); !errs.IsCategory(err, errs.CategoryConfiguration) {
			t.Errorf("%s: got %v, want a configuration error", name, err)
		}
	}
}

// With AuditConfig.OmitIPAndAgent the event of a refusal records neither
// the address nor the key, which for a rule per address is the address.
func TestRateLimitRefusalOmitsTheAddressWhenConfigured(t *testing.T) {
	tel, rec := telemetrytest.New()
	rl := &DefaultRateLimiter{tel: tel, audit: core.AuditConfig{OmitIPAndAgent: true}}
	ctx := context.Background()
	err := rl.evaluate(ctx, "signin", "signin:203.0.113.7", "203.0.113.7", fixedLimiter{allowed: false}, core.Limit{}, "", 0)
	if !errs.IsCategory(err, errs.CategoryRateLimited) {
		t.Fatalf("got %v", err)
	}
	events := rec.Audit.OfType(telemetry.AuditRateLimitExceeded)
	if len(events) != 1 || events[0].IPAddress != "" || events[0].Metadata["key"] != nil || events[0].Metadata["rule"] != "signin" {
		t.Errorf("audit events = %+v, want one event with the rule and without the address or the key", events)
	}
}
