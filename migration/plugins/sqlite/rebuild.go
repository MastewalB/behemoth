package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	behemotherr "github.com/MastewalB/behemoth/errors"
)

// rebuildTablePrefix names the temporary table a rebuild copies rows into.
const rebuildTablePrefix = "_behemoth_rebuild_"

// rebuildTable performs SQLite's generalized ALTER TABLE procedure
// (https://www.sqlite.org/lang_altertable.html#otheralter):
//
//  1. read the table's CREATE TABLE statement from sqlite_master
//  2. let mutate edit it (add/replace/drop a column or table constraint)
//  3. create the edited table under a temporary name and copy every column
//     the old and new tables share
//  4. drop the old table, rename the new one into place
//  5. recreate the old table's indexes (filtered by keepIndex) and triggers
//
// The CREATE statement is edited textually rather than regenerated from PRAGMA
// introspection, so everything the driver doesn't touch — CHECK constraints,
// AUTOINCREMENT, collations, named constraints, WITHOUT ROWID/STRICT — survives
// untouched. Must run inside inMigrationTx, which disables foreign key
// enforcement for the duration and validates it before commit.
func (d *SQLiteDriver) rebuildTable(
	ctx context.Context,
	tx execQuerier,
	table string,
	mutate func(s *tableSQL) error,
	keepIndex func(idx liveIndex) bool,
) error {
	const op = "SQLiteDriver.rebuildTable"
	phys := d.resolver.Resolve(table)

	var createSQL string
	err := tx.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ? COLLATE NOCASE", phys).Scan(&createSQL)
	if errors.Is(err, sql.ErrNoRows) {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationTableNotFound, fmt.Errorf("table %q does not exist", phys))
	}
	if err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationQueryFailed, err)
	}

	s, err := parseCreateTable(createSQL)
	if err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationParseFailed, fmt.Errorf("table %q: %w", phys, err))
	}
	if err := mutate(s); err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationRebuildFailed, fmt.Errorf("table %q: %w", phys, err))
	}

	// Everything attached to the old table is captured before it is dropped.
	indexes, err := loadIndexes(ctx, tx, phys)
	if err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	triggers, err := querySQLColumn(ctx, tx, "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ? COLLATE NOCASE", phys)
	if err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	seq, hasSeq, err := loadSequence(ctx, tx, phys)
	if err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	oldCols, err := insertableColumns(ctx, tx, phys)
	if err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationQueryFailed, err)
	}

	tmp := rebuildTablePrefix + phys
	if err := execDDL(ctx, tx, op, s.render(tmp)); err != nil {
		return err
	}
	newCols, err := insertableColumns(ctx, tx, tmp)
	if err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationQueryFailed, err)
	}

	var shared []string
	for _, c := range newCols {
		if containsFold(oldCols, c) {
			shared = append(shared, quoteIdent(c))
		}
	}
	if len(shared) > 0 {
		cols := strings.Join(shared, ", ")
		if err := execDDL(ctx, tx, op, fmt.Sprintf("INSERT INTO %s (%s) SELECT %s FROM %s", quoteIdent(tmp), cols, cols, quoteIdent(phys))); err != nil {
			return err
		}
	}

	if err := execDDL(ctx, tx, op, "DROP TABLE "+quoteIdent(phys)); err != nil {
		return err
	}
	if err := renameTableLegacy(ctx, tx, tmp, phys); err != nil {
		return err
	}

	for _, idx := range indexes {
		if keepIndex != nil && !keepIndex(idx) {
			continue
		}
		if err := execDDL(ctx, tx, op, idx.sql); err != nil {
			return err
		}
	}
	for _, trig := range triggers {
		if err := execDDL(ctx, tx, op, trig); err != nil {
			return err
		}
	}
	// Copying rows only raises sqlite_sequence to MAX(rowid); restore the old
	// high-water mark so AUTOINCREMENT never reuses ids of deleted rows.
	if hasSeq {
		if _, err := tx.ExecContext(ctx, "UPDATE sqlite_sequence SET seq = MAX(seq, ?) WHERE name = ?", seq, phys); err != nil {
			return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationExecFailed, err)
		}
	}
	return nil
}

// renameTableLegacy renames with legacy_alter_table on, so SQLite does not
// try to rewrite references in other tables/views/triggers: those already
// name the final table, and with the old table dropped a modern-mode rename
// fails on any view that references it.
func renameTableLegacy(ctx context.Context, tx execQuerier, from, to string) error {
	const op = "SQLiteDriver.rebuildTable"
	var legacy bool
	if err := tx.QueryRowContext(ctx, "PRAGMA legacy_alter_table").Scan(&legacy); err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationPragmaFailed, err)
	}
	if !legacy {
		if err := execDDL(ctx, tx, op, "PRAGMA legacy_alter_table = ON"); err != nil {
			return err
		}
	}
	renameErr := execDDL(ctx, tx, op, fmt.Sprintf("ALTER TABLE %s RENAME TO %s", quoteIdent(from), quoteIdent(to)))
	if !legacy {
		if err := execDDL(ctx, tx, op, "PRAGMA legacy_alter_table = OFF"); err != nil && renameErr == nil {
			return err
		}
	}
	return renameErr
}

type liveIndex struct {
	name    string
	sql     string
	columns []string // plain column names; expression parts are omitted
}

// loadIndexes returns the explicitly created indexes of table. Indexes backing
// PRIMARY KEY/UNIQUE constraints (sqlite_autoindex_*) have NULL sql and are
// recreated by the CREATE TABLE statement itself.
func loadIndexes(ctx context.Context, tx execQuerier, table string) ([]liveIndex, error) {
	rows, err := tx.QueryContext(ctx, "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = ? COLLATE NOCASE AND sql IS NOT NULL", table)
	if err != nil {
		return nil, err
	}
	var out []liveIndex
	for rows.Next() {
		var idx liveIndex
		if err := rows.Scan(&idx.name, &idx.sql); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, idx)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range out {
		cols, err := querySQLColumn(ctx, tx, "SELECT name FROM pragma_index_info(?) WHERE name IS NOT NULL ORDER BY seqno", out[i].name)
		if err != nil {
			return nil, err
		}
		out[i].columns = cols
	}
	return out, nil
}

// insertableColumns lists the table's ordinary columns, excluding generated
// columns (hidden 2/3), which can't be the target of an INSERT.
func insertableColumns(ctx context.Context, tx execQuerier, table string) ([]string, error) {
	return querySQLColumn(ctx, tx, "SELECT name FROM pragma_table_xinfo(?) WHERE hidden = 0 ORDER BY cid", table)
}

func loadSequence(ctx context.Context, tx execQuerier, table string) (int64, bool, error) {
	var exists bool
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = 'sqlite_sequence'").Scan(&exists); err != nil || !exists {
		return 0, false, err
	}
	var seq int64
	err := tx.QueryRowContext(ctx, "SELECT seq FROM sqlite_sequence WHERE name = ?", table).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return seq, err == nil, err
}

func querySQLColumn(ctx context.Context, tx execQuerier, query string, args ...any) ([]string, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---- CREATE TABLE parsing ----

type itemKind int

const (
	itemColumn itemKind = iota
	itemPrimaryKey
	itemUnique
	itemCheck
	itemForeignKey
)

// tableItem is one top-level, comma-separated entry of a CREATE TABLE body:
// a column definition or a table constraint.
type tableItem struct {
	text    string
	kind    itemKind
	name    string   // column name, or constraint name ("" if unnamed)
	columns []string // PRIMARY KEY / UNIQUE / FOREIGN KEY: the local columns
	tokens  []token
}

type tableSQL struct {
	items  []tableItem
	suffix string // table options after the closing paren, e.g. " WITHOUT ROWID"
}

func parseCreateTable(stmt string) (*tableSQL, error) {
	open := -1
	for i := 0; i < len(stmt); {
		if j := skipNonCode(stmt, i); j != i {
			i = j
			continue
		}
		if stmt[i] == '(' {
			open = i
			break
		}
		i++
	}
	if open < 0 {
		return nil, fmt.Errorf("no column list in %q", stmt)
	}
	end := matchParen(stmt, open)
	if end < 0 {
		return nil, fmt.Errorf("unbalanced parentheses in %q", stmt)
	}

	s := &tableSQL{suffix: stmt[end+1:]}
	for _, part := range splitTopLevel(stmt[open+1 : end]) {
		item, err := classifyItem(part)
		if err != nil {
			return nil, err
		}
		s.items = append(s.items, item)
	}
	return s, nil
}

func classifyItem(text string) (tableItem, error) {
	toks := tokenize(text)
	if len(toks) == 0 {
		return tableItem{}, fmt.Errorf("empty table item")
	}
	item := tableItem{text: text, tokens: toks}

	rest := toks
	if toks[0].isKeyword("CONSTRAINT") {
		if len(toks) < 3 {
			return tableItem{}, fmt.Errorf("malformed constraint %q", text)
		}
		item.name = toks[1].text
		rest = toks[2:]
	}

	switch {
	case rest[0].isKeyword("PRIMARY"):
		item.kind = itemPrimaryKey
	case rest[0].isKeyword("UNIQUE"):
		item.kind = itemUnique
	case rest[0].isKeyword("CHECK"):
		item.kind = itemCheck
	case rest[0].isKeyword("FOREIGN"):
		item.kind = itemForeignKey
	default:
		if item.name != "" {
			return tableItem{}, fmt.Errorf("unknown constraint %q", text)
		}
		item.kind = itemColumn
		item.name = toks[0].text
		return item, nil
	}

	// The first parenthesized group after the keyword lists the local columns.
	if item.kind != itemCheck {
		for _, t := range rest {
			if t.paren {
				for _, c := range splitTopLevel(t.text) {
					if ct := tokenize(c); len(ct) > 0 {
						item.columns = append(item.columns, ct[0].text)
					}
				}
				break
			}
		}
	}
	return item, nil
}

func (s *tableSQL) render(table string) string {
	texts := make([]string, len(s.items))
	for i, it := range s.items {
		texts[i] = it.text
	}
	return fmt.Sprintf("CREATE TABLE %s (%s)%s", quoteIdent(table), strings.Join(texts, ", "), s.suffix)
}

func (s *tableSQL) findColumn(name string) int {
	for i, it := range s.items {
		if it.kind == itemColumn && strings.EqualFold(it.name, name) {
			return i
		}
	}
	return -1
}

func (s *tableSQL) findConstraint(name string) int {
	for i, it := range s.items {
		if it.kind != itemColumn && it.name != "" && strings.EqualFold(it.name, name) {
			return i
		}
	}
	return -1
}

func (s *tableSQL) removeItem(i int) {
	s.items = append(s.items[:i], s.items[i+1:]...)
}

// appendColumn inserts after the last column definition: SQLite requires all
// column definitions to precede the table constraints.
func (s *tableSQL) appendColumn(def string) {
	at := 0
	for i, it := range s.items {
		if it.kind == itemColumn {
			at = i + 1
		}
	}
	item, _ := classifyItem(def)
	s.items = append(s.items[:at], append([]tableItem{item}, s.items[at:]...)...)
}

func (s *tableSQL) appendConstraint(text string) {
	item, _ := classifyItem(text)
	s.items = append(s.items, item)
}

func (s *tableSQL) replaceColumn(name, def string) error {
	i := s.findColumn(name)
	if i < 0 {
		return fmt.Errorf("column %q not found", name)
	}
	item, err := classifyItem(def)
	if err != nil {
		return err
	}
	s.items[i] = item
	return nil
}

// dropColumn removes the column and every table constraint involving it —
// the same cascade Postgres applies on DROP COLUMN.
func (s *tableSQL) dropColumn(name string) error {
	i := s.findColumn(name)
	if i < 0 {
		return fmt.Errorf("column %q not found", name)
	}
	s.removeItem(i)

	kept := s.items[:0]
	for _, it := range s.items {
		switch it.kind {
		case itemPrimaryKey, itemUnique, itemForeignKey:
			if containsFold(it.columns, name) {
				continue
			}
		case itemCheck:
			if referencesIdent(it.tokens, name) {
				continue
			}
		}
		kept = append(kept, it)
	}
	s.items = kept

	if s.findColumnCount() == 0 {
		return fmt.Errorf("cannot drop %q: it is the table's only column", name)
	}
	return nil
}

func (s *tableSQL) findColumnCount() int {
	n := 0
	for _, it := range s.items {
		if it.kind == itemColumn {
			n++
		}
	}
	return n
}

func (s *tableSQL) hasTablePrimaryKey() bool {
	for _, it := range s.items {
		if it.kind == itemPrimaryKey {
			return true
		}
	}
	return false
}

func (s *tableSQL) hasInlinePrimaryKey() bool {
	for _, it := range s.items {
		if it.kind == itemColumn && it.hasInlinePrimaryKey() {
			return true
		}
	}
	return false
}

func (s *tableSQL) columnHasInlinePrimaryKey(name string) bool {
	i := s.findColumn(name)
	return i >= 0 && s.items[i].hasInlinePrimaryKey()
}

func (it tableItem) hasInlinePrimaryKey() bool {
	for _, t := range it.tokens[1:] { // tokens[0] is the column name
		if t.isKeyword("PRIMARY") {
			return true
		}
	}
	return false
}

// referencesIdent reports whether name appears as an identifier anywhere in
// toks, including nested parenthesized expressions.
func referencesIdent(toks []token, name string) bool {
	for _, t := range toks {
		if t.paren {
			if referencesIdent(tokenize(t.text), name) {
				return true
			}
			continue
		}
		if !t.literal && strings.EqualFold(t.text, name) {
			return true
		}
	}
	return false
}

// ---- Tokenizer ----

type token struct {
	text    string // unquoted identifier/word, or the inner text of a (...) group
	paren   bool   // a parenthesized group
	quoted  bool   // a quoted identifier ("x", `x`, [x])
	literal bool   // a string literal ('x')
}

func (t token) isKeyword(kw string) bool {
	return !t.paren && !t.quoted && !t.literal && strings.EqualFold(t.text, kw)
}

// tokenize splits s into top-level words, quoted identifiers, string literals
// and parenthesized groups; punctuation and comments are dropped.
func tokenize(s string) []token {
	var out []token
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			end := matchParen(s, i)
			if end < 0 {
				end = len(s)
			}
			out = append(out, token{text: s[i+1 : min(end, len(s))], paren: true})
			i = end + 1
		case c == '\'' || c == '"' || c == '`' || c == '[':
			end := skipNonCode(s, i)
			out = append(out, token{text: unquote(s[i:end]), quoted: c != '\'', literal: c == '\''})
			i = end
		case isWordChar(c):
			j := i
			for j < len(s) && isWordChar(s[j]) {
				j++
			}
			out = append(out, token{text: s[i:j]})
			i = j
		default:
			if j := skipNonCode(s, i); j != i {
				i = j // comment
			} else {
				i++
			}
		}
	}
	return out
}

func isWordChar(c byte) bool {
	return c == '_' || c == '$' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

func unquote(q string) string {
	if len(q) < 2 {
		return q
	}
	switch q[0] {
	case '[':
		return q[1 : len(q)-1]
	case '"', '`', '\'':
		inner := q[1 : len(q)-1]
		return strings.ReplaceAll(inner, string(q[0])+string(q[0]), string(q[0]))
	}
	return q
}

// skipNonCode returns the index just past a quoted token or comment starting
// at i, or i itself if none starts there.
func skipNonCode(s string, i int) int {
	switch s[i] {
	case '\'', '"', '`':
		q := s[i]
		for j := i + 1; j < len(s); j++ {
			if s[j] == q {
				if j+1 < len(s) && s[j+1] == q { // doubled quote is an escaped quote
					j++
					continue
				}
				return j + 1
			}
		}
		return len(s)
	case '[':
		if k := strings.IndexByte(s[i:], ']'); k >= 0 {
			return i + k + 1
		}
		return len(s)
	case '-':
		if i+1 < len(s) && s[i+1] == '-' {
			if k := strings.IndexByte(s[i:], '\n'); k >= 0 {
				return i + k + 1
			}
			return len(s)
		}
	case '/':
		if i+1 < len(s) && s[i+1] == '*' {
			if k := strings.Index(s[i+2:], "*/"); k >= 0 {
				return i + 2 + k + 2
			}
			return len(s)
		}
	}
	return i
}

// matchParen returns the index of the ')' closing the '(' at open, or -1.
func matchParen(s string, open int) int {
	depth := 0
	for i := open; i < len(s); {
		if j := skipNonCode(s, i); j != i {
			i = j
			continue
		}
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
		i++
	}
	return -1
}

// splitTopLevel splits s on commas outside parentheses, quotes and comments.
func splitTopLevel(s string) []string {
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(s); {
		if j := skipNonCode(s, i); j != i {
			i = j
			continue
		}
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
		i++
	}
	if last := strings.TrimSpace(s[start:]); last != "" {
		parts = append(parts, last)
	}
	return parts
}
