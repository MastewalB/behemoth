package dispatch

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/utils"
)

type DefaultHookRegistry struct {
	mu      sync.Mutex
	catalog types.HookCatalog
	pending map[types.HookPoint][]registeredHandler // unordered until FreezeChains resolves it
	frozen  bool
}

// NewHookRegistry returns an empty registry for the handlers of catalog's
// points. A handler is registered through For.
func NewHookRegistry(catalog types.HookCatalog) *DefaultHookRegistry {
	return &DefaultHookRegistry{catalog: catalog, pending: map[types.HookPoint][]registeredHandler{}}
}

func (r *DefaultHookRegistry) register(point types.HookPoint, phase types.HookPhase, plugin string, fn any, opts *types.HookOptions) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frozen {
		return errs.NewConfigurationError("HookRegistry.register", "cannot register after chains have been frozen", nil)
	}
	def, ok := r.catalog.Lookup(point)
	if !ok {
		return errs.NewConfigurationError("HookRegistry.register", fmt.Sprintf("point %q was never declared", point), nil)
	}
	if def.Phase != phase {
		return errs.NewConfigurationError("HookRegistry.register",
			fmt.Sprintf("point %q is phase %q, cannot register a %q handler on it", point, def.Phase, phase), nil)
	}

	// One handler per owner on a point: chain ordering (Before/After,
	// tie-breaks) identifies a handler by its owner's name, so a second one
	// could not be placed. An owner that needs two steps combines them in
	// one handler.
	for _, existing := range r.pending[point] {
		if existing.plugin == plugin {
			return errs.NewConfigurationError("HookRegistry.register",
				fmt.Sprintf("%q already registered a handler on point %q; an owner may register one handler per point", plugin, point), nil)
		}
	}

	rh := registeredHandler{plugin: plugin, handler: fn, priority: types.PriorityNormal}
	if opts != nil {
		rh.priority, rh.before, rh.after = opts.Priority, opts.Before, opts.After
	}
	r.pending[point] = append(r.pending[point], rh)
	return nil
}

// scopedHookRegistry is the types.HookRegistry an owner registers through. It
// injects the owner's name: a plugin's Register(reg HookRegistry) call
// receives one of these, typed as the interface, and can't override `owner`.
// DefaultHookRegistry has no registering methods of its own, so a handler
// can't be registered without an owner.
type scopedHookRegistry struct {
	inner *DefaultHookRegistry
	owner string
}

func (s *scopedHookRegistry) OnBefore(point types.HookPoint, fn types.BeforeHookFunc, opts *types.HookOptions) error {
	return s.inner.register(point, types.BeforeHookPhase, s.owner, fn, opts)
}

func (s *scopedHookRegistry) OnAfter(point types.HookPoint, fn types.AfterHookFunc, opts *types.HookOptions) error {
	return s.inner.register(point, types.AfterHookPhase, s.owner, fn, opts)
}

func (s *scopedHookRegistry) OnFailed(point types.HookPoint, fn types.FailedHookFunc, opts *types.HookOptions) error {
	return s.inner.register(point, types.FailedHookPhase, s.owner, fn, opts)
}

// For returns the registry through which owner registers its handlers. It
// records owner as the plugin of each handler it takes, and it is the only way
// to register one. Boot gives one to each plugin and one to the application.
func (r *DefaultHookRegistry) For(owner string) types.HookRegistry {
	return &scopedHookRegistry{inner: r, owner: owner}
}

// Chains holds the frozen chain of handlers of every hook point: what
// FreezeChains builds and a dispatcher runs.
type Chains map[types.HookPoint][]registeredHandler

// FreezeChains orders the handlers of every point of catalog, by their
// priorities, their Before and After lists, and pluginOrder, and freezes
// registry: it takes no handler afterwards.
func FreezeChains(catalog types.HookCatalog, registry *DefaultHookRegistry, pluginOrder []string) (Chains, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	frozen := make(map[types.HookPoint][]registeredHandler)
	for _, def := range catalog.All() {
		resolved, err := resolvePointOrder(def.Point, registry.pending[def.Point], pluginOrder)
		if err != nil {
			return nil, err
		}
		frozen[def.Point] = resolved
	}

	registry.frozen = true
	return frozen, nil
}

func resolvePointOrder(point types.HookPoint, handlers []registeredHandler, pluginOrder []string) ([]registeredHandler, error) {
	if len(handlers) <= 1 {
		return handlers, nil
	}

	buckets := map[types.HookPriority][]registeredHandler{}
	priorityOf := map[string]types.HookPriority{}

	for _, h := range handlers {
		buckets[h.priority] = append(buckets[h.priority], h)
		priorityOf[h.plugin] = h.priority
	}

	priorities := make([]types.HookPriority, 0, len(buckets))
	for p := range buckets {
		priorities = append(priorities, p)
	}
	sort.Slice(priorities, func(i, j int) bool { return priorities[i] < priorities[j] }) // Highest(-100) first, ascending numeric order

	var result []registeredHandler
	for _, p := range priorities {
		bucket := buckets[p]

		// contradiction check: a Before/After constraint that contradicting bucket ordering is a boot error
		for _, h := range bucket {
			for _, mustBeBefore := range h.before {
				if otherP, ok := priorityOf[mustBeBefore]; ok && otherP < p {
					return nil, errs.NewConfigurationError("HookRegistry.Freeze",
						fmt.Sprintf("point %q: %q wants to run before %q, but %q sits in a higher-priority bucket", point, h.plugin, mustBeBefore, mustBeBefore), nil)
				}
			}
			for _, mustBeAfter := range h.after {
				if otherP, ok := priorityOf[mustBeAfter]; ok && otherP > p {
					return nil, errs.NewConfigurationError("HookRegistry.Freeze",
						fmt.Sprintf("point %q: %q wants to run after %q, but %q sits in a lower-priority bucket", point, h.plugin, mustBeAfter, mustBeAfter), nil)
				}
			}
		}

		if len(bucket) == 1 {
			result = append(result, bucket[0])
			continue
		}
		ordered, err := topoSortBucket(point, bucket, pluginOrder)
		if err != nil {
			return nil, err
		}
		result = append(result, ordered...)
	}
	return result, nil

}

// topoSortBucket resolves handler order within one priority bucket with
// KahnSort, the sort plugin ordering uses. An edge comes from a Before or
// After that names an owner with a handler in the same bucket; a constraint
// naming any other owner adds none. Handlers the edges leave unordered run
// in plugin boot order (pluginOrder, the application last), so a plugin's
// handler runs after those of the plugins it depends on. A cycle is a
// configuration error.
func topoSortBucket(point types.HookPoint, bucket []registeredHandler, pluginOrder []string) ([]registeredHandler, error) {
	byPlugin := make(map[string]registeredHandler, len(bucket))
	for _, h := range bucket {
		byPlugin[h.plugin] = h
	}

	// indexOf gives O(1) lookup into the finalized plugin boot order
	indexOf := make(map[string]int, len(pluginOrder))
	for i, name := range pluginOrder {
		indexOf[name] = i
	}
	registrationOrder := func(a, b string) bool { return indexOf[a] < indexOf[b] }

	graphMap := map[string][]string{}
	for name := range byPlugin {
		graphMap[name] = nil // ensure every handler-plugin appears even with zero constraints
	}

	for _, h := range bucket {
		for _, mustBeBefore := range h.before {
			if _, exists := byPlugin[mustBeBefore]; exists { // constraint naming a plugin outside this bucket/point is a no-op, per the ordering round
				graphMap[h.plugin] = append(graphMap[h.plugin], mustBeBefore)
			}
		}
		for _, mustBeAfter := range h.after {
			if _, exists := byPlugin[mustBeAfter]; exists {
				graphMap[mustBeAfter] = append(graphMap[mustBeAfter], h.plugin)
			}
		}
	}

	sortedNames, cyclePath, ok := utils.KahnSort(graphMap, registrationOrder)
	if !ok {
		return nil, errs.NewConfigurationError("HookRegistry.Freeze",
			fmt.Sprintf("point %q: circular handler ordering: %s", point, strings.Join(cyclePath, " -> ")), nil)
	}

	ordered := make([]registeredHandler, len(sortedNames))
	for i, name := range sortedNames {
		ordered[i] = byPlugin[name]
	}
	return ordered, nil
}

type registeredHandler struct {
	plugin   string
	priority types.HookPriority
	before   []string
	after    []string
	handler  any // BeforeHookFunc | AfterHookFunc | FailedHookFunc, resolved by the point's declared Phase
}
