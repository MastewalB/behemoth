package schema

import (
	"fmt"
	"slices"
	"sort"
	"sync"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
)

type Registry interface {
	Declare(model behemoth.Model, table Table) error

	// ExtendColumn, ExtendIndex and ExtendForeignKey add to a table another
	// plugin declares. The table may be declared before or after the
	// contribution; either way a name that clashes with the base table or with
	// another contribution is rejected, and Freeze rejects contributions to a
	// table that was never declared.
	ExtendColumn(contribution ColumnContribution) error
	ExtendIndex(contribution IndexContribution) error
	ExtendForeignKey(contribution ForeignKeyContribution) error

	// Lookup returns the fully merged table i.e. base Declare() shape plus
	// every accepted ExtendColumn/ExtendIndex/ExtendForeignKey contribution. Every
	// consumer downstream (the differ, the generator) sees one resolved
	// Table per table name; nothing downstream needs to know or care
	// which parts came from Declare vs. Extend.
	Lookup(name string) (Table, bool)
	LookupModel(name string) (behemoth.Model, bool)
	All() []Table
	Freeze() error
}

type DefaultRegistry struct {
	mu             sync.RWMutex
	tables         map[string]Table // base shapes from Declare
	models         map[string]behemoth.Model
	columnExts     map[string][]ColumnContribution // keyed by table name
	indexExts      map[string][]IndexContribution
	foreignKeyExts map[string][]ForeignKeyContribution
	frozen         bool
}

func NewRegistry() *DefaultRegistry {
	return &DefaultRegistry{
		tables:         map[string]Table{},
		models:         map[string]behemoth.Model{},
		columnExts:     map[string][]ColumnContribution{},
		indexExts:      map[string][]IndexContribution{},
		foreignKeyExts: map[string][]ForeignKeyContribution{},
	}
}

var _ Registry = (*DefaultRegistry)(nil)

// Declare rejects a duplicate table name from a different owner
// A plugin re-declaring its own table across repeated Declare calls is equally rejected
// Declare is write-once per table(not merge).
func (r *DefaultRegistry) Declare(model behemoth.Model, table Table) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.frozen {
		return behemotherr.NewConfigurationError("SchemaRegistry.Declare", "cannot Declare after boot has completed", nil)
	}

	if model.SchemaName() != table.Name {
		return behemotherr.NewConfigurationError("SchemaRegistry.Declare",
			fmt.Sprintf("model.SchemaName() = %q does not match Table.Name = %q", model.SchemaName(), table.Name), nil)
	}
	if existing, dup := r.tables[table.Name]; dup {
		return behemotherr.NewConfigurationError("SchemaRegistry.Declare",
			fmt.Sprintf("table %q already declared by %q", table.Name, existing.Owner), nil)
	}
	// Contributions may have arrived before this Declare — check them against
	// the base shape now, the same check Extend* runs when the table exists first.
	for _, c := range r.columnExts[table.Name] {
		if err := checkBaseClash("SchemaRegistry.Declare", "column", table, c.Column.Name, c.Owner, columnNames(table.Columns)); err != nil {
			return err
		}
	}
	for _, c := range r.indexExts[table.Name] {
		if err := checkBaseClash("SchemaRegistry.Declare", "index", table, c.Index.Name, c.Owner, indexNames(table.Indexes)); err != nil {
			return err
		}
	}
	for _, c := range r.foreignKeyExts[table.Name] {
		if err := checkBaseClash("SchemaRegistry.Declare", "foreign key", table, c.ForeignKey.Name, c.Owner, foreignKeyNames(table.ForeignKeys)); err != nil {
			return err
		}
	}

	r.tables[table.Name] = table
	r.models[table.Name] = model
	return nil
}

func (r *DefaultRegistry) ExtendColumn(c ColumnContribution) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	const op = "SchemaRegistry.ExtendColumn"
	if r.frozen {
		return behemotherr.NewConfigurationError(op, "cannot extend after boot has completed", nil)
	}
	// Table need not exist YET at the moment of this call — plugin
	// dependency order guarantees the owning plugin's Declare ran first if
	// a real dependency edge was declared, but the existence check is
	// deferred to Freeze, and the base-clash check to Declare, when it doesn't.
	if base, ok := r.tables[c.Table]; ok {
		if err := checkBaseClash(op, "column", base, c.Column.Name, c.Owner, columnNames(base.Columns)); err != nil {
			return err
		}
	}
	for _, existing := range r.columnExts[c.Table] {
		if existing.Column.Name == c.Column.Name {
			return behemotherr.NewConfigurationError(op,
				fmt.Sprintf("table %q column %q already contributed by %q", c.Table, c.Column.Name, existing.Owner), nil)
		}
	}
	r.columnExts[c.Table] = append(r.columnExts[c.Table], c)
	return nil
}

func (r *DefaultRegistry) ExtendIndex(c IndexContribution) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	const op = "SchemaRegistry.ExtendIndex"
	if r.frozen {
		return behemotherr.NewConfigurationError(op, "cannot extend after boot has completed", nil)
	}
	// Same deferred checks as ExtendColumn.
	if base, ok := r.tables[c.Table]; ok {
		if err := checkBaseClash(op, "index", base, c.Index.Name, c.Owner, indexNames(base.Indexes)); err != nil {
			return err
		}
	}
	for _, existing := range r.indexExts[c.Table] {
		if existing.Index.Name == c.Index.Name {
			return behemotherr.NewConfigurationError(op,
				fmt.Sprintf("table %q index %q already contributed by %q", c.Table, c.Index.Name, existing.Owner), nil)
		}
	}
	r.indexExts[c.Table] = append(r.indexExts[c.Table], c)
	return nil
}

// ExtendForeignKey adds a foreign key to a table another plugin declares —
// e.g. a plugin linking its own contributed column to a table it doesn't own.
// Planning emits it as its own OpAddForeignKey, like every other foreign key.
func (r *DefaultRegistry) ExtendForeignKey(c ForeignKeyContribution) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	const op = "SchemaRegistry.ExtendForeignKey"
	if r.frozen {
		return behemotherr.NewConfigurationError(op, "cannot extend after boot has completed", nil)
	}
	// Same deferred checks as ExtendColumn.
	if base, ok := r.tables[c.Table]; ok {
		if err := checkBaseClash(op, "foreign key", base, c.ForeignKey.Name, c.Owner, foreignKeyNames(base.ForeignKeys)); err != nil {
			return err
		}
	}
	for _, existing := range r.foreignKeyExts[c.Table] {
		if existing.ForeignKey.Name == c.ForeignKey.Name {
			return behemotherr.NewConfigurationError(op,
				fmt.Sprintf("table %q foreign key %q already contributed by %q", c.Table, c.ForeignKey.Name, existing.Owner), nil)
		}
	}
	r.foreignKeyExts[c.Table] = append(r.foreignKeyExts[c.Table], c)
	return nil
}

// checkBaseClash rejects a contribution whose name the declaring plugin
// already uses on the base table — a contribution may add, never redefine.
func checkBaseClash(op, kind string, base Table, name, owner string, baseNames []string) error {
	if slices.Contains(baseNames, name) {
		return behemotherr.NewConfigurationError(op,
			fmt.Sprintf("table %q %s %q is declared by %q and cannot also be contributed by %q", base.Name, kind, name, base.Owner, owner), nil)
	}
	return nil
}

func columnNames(cols []Column) []string {
	names := make([]string, len(cols))
	for i, c := range cols {
		names[i] = c.Name
	}
	return names
}

func indexNames(idxs []Index) []string {
	names := make([]string, len(idxs))
	for i, idx := range idxs {
		names[i] = idx.Name
	}
	return names
}

func foreignKeyNames(fks []ForeignKey) []string {
	names := make([]string, len(fks))
	for i, fk := range fks {
		names[i] = fk.Name
	}
	return names
}

func (r *DefaultRegistry) Lookup(name string) (Table, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lookupLocked(name)
}

// lookupLocked merges the base shape with its contributions; callers hold r.mu.
func (r *DefaultRegistry) lookupLocked(name string) (Table, bool) {
	base, ok := r.tables[name]
	if !ok {
		return Table{}, false
	}
	merged := base // copy
	merged.Columns = append(append([]Column{}, base.Columns...), extractColumns(r.columnExts[name])...)
	merged.Indexes = append(append([]Index{}, base.Indexes...), extractIndexes(r.indexExts[name])...)
	merged.ForeignKeys = append(append([]ForeignKey{}, base.ForeignKeys...), extractForeignKeys(r.foreignKeyExts[name])...)
	return merged, true
}

func (r *DefaultRegistry) LookupModel(name string) (behemoth.Model, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.models[name]
	return m, ok
}

// All returns every declared table in its merged form (same shape as Lookup),
// sorted by name so every consumer — diffing, baseline generation, resolver
// building — sees a deterministic order.
func (r *DefaultRegistry) All() []Table {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.tables))
	for name := range r.tables {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]Table, 0, len(names))
	for _, name := range names {
		t, _ := r.lookupLocked(name)
		out = append(out, t)
	}
	return out
}

func (r *DefaultRegistry) Freeze() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for table, contributions := range r.columnExts {
		if err := r.checkDeclared(table, contributions[0].Owner); err != nil {
			return err
		}
	}
	for table, contributions := range r.indexExts {
		if err := r.checkDeclared(table, contributions[0].Owner); err != nil {
			return err
		}
	}
	for table, contributions := range r.foreignKeyExts {
		if err := r.checkDeclared(table, contributions[0].Owner); err != nil {
			return err
		}
	}
	r.frozen = true
	return nil
}

func (r *DefaultRegistry) checkDeclared(table, owner string) error {
	if _, ok := r.tables[table]; !ok {
		return behemotherr.NewConfigurationError("SchemaRegistry.Freeze",
			fmt.Sprintf("table %q was never declared, but %q attempted to extend it", table, owner), nil)
	}
	return nil
}

func extractColumns(cc []ColumnContribution) []Column {
	columns := make([]Column, len(cc))
	for i, c := range cc {
		columns[i] = c.Column
	}
	return columns
}

func extractIndexes(ic []IndexContribution) []Index {
	indexes := make([]Index, len(ic))
	for i, ind := range ic {
		indexes[i] = ind.Index
	}
	return indexes
}

func extractForeignKeys(fkc []ForeignKeyContribution) []ForeignKey {
	foreignKeys := make([]ForeignKey, len(fkc))
	for i, fk := range fkc {
		foreignKeys[i] = fk.ForeignKey
	}
	return foreignKeys
}
