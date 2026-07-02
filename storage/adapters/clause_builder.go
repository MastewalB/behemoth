package adapters

import (
	"fmt"
	"strings"

	"github.com/MastewalB/behemoth/clause"
)

// ClauseOptions defines the options for building SQL WHERE clauses, including placeholder format and numbering.
type ClauseOptions struct {
	// The placeholder string in the clause. Defaults to "?" if not specified
	Placeholder string

	// Whether to use numbered placeholders (e.g., $1, $2, or @p1, @p2). Defaults to false if not specified
	UseNumberedPlaceholder bool

	// The starting number for numbered placeholders. Defaults to 1 if not specified
	Number int
}

// defaultClauseOption provides basic settings for SQL WHERE clauses compatible for common databases and ORMs like SQLite, GORM, and Bun.
var DefaultClauseOption = &ClauseOptions{
	Placeholder:            "?",
	UseNumberedPlaceholder: false,
	Number:                 1,
}

// BuildSQLWhereClause constructs SQL WHERE clause from the given expression.
// It uses the provided options to determine the placeholder format and numbering.
func BuildSQLWhereClause(expr *clause.Expression, options *ClauseOptions) (string, []any) {

	placeholder := "?"
	useNumberedPlaceholder := false
	startIndex := 1

	if options != nil {
		placeholder = options.Placeholder
		useNumberedPlaceholder = options.UseNumberedPlaceholder

		if useNumberedPlaceholder {
			startIndex = options.Number
		}
	}

	newOptions := ClauseOptions{
		Placeholder:            placeholder,
		UseNumberedPlaceholder: useNumberedPlaceholder,
		Number:                 startIndex,
	}

	return buildSQLWhereClause(expr, newOptions)
}

func buildSQLWhereClause(expr *clause.Expression, options ClauseOptions) (string, []any) {
	if expr == nil {
		return "", nil
	}

	var queryParts []string
	var args []any
	var formatString string
	var logicalOp clause.Logic = clause.OpAnd

	totalConditions := len(expr.Conditions) + len(expr.Children)
	if totalConditions > 1 {
		formatString = "(%s)"
	} else {
		formatString = "%s"
	}

	if expr.Logic != "" {
		logicalOp = expr.Logic
	}

	if len(expr.Children) > 0 {
		for _, child := range expr.Children {
			subQuery, subArgs := buildSQLWhereClause(child, options)
			queryParts = append(queryParts, subQuery)
			args = append(args, subArgs...)
			options.Number += len(subArgs)
		}
	}
	for _, cond := range expr.Conditions {
		subQuery, subArgs := buildSingleConditionSQL(cond, options)
		queryParts = append(queryParts, subQuery)
		args = append(args, subArgs...)
		options.Number += len(subArgs)
	}

	joinedQuery := strings.Join(queryParts, fmt.Sprintf(" %s ", logicalOp))

	return fmt.Sprintf(formatString, joinedQuery), args
}

func buildSingleConditionSQL(cond clause.Condition, options ClauseOptions) (string, []any) {

	// By default, the placeholder is the string character specified in options.Placeholder.
	// If UseNumberedPlaceholder is true, we append the current number to the placeholder.
	paramValuePlaceholder := options.Placeholder
	if options.UseNumberedPlaceholder {
		paramValuePlaceholder = fmt.Sprintf("%s%d", paramValuePlaceholder, options.Number)
	}

	switch cond.Operator {
	case clause.OpEqual:
		return fmt.Sprintf("(%s = %s)", cond.Field, paramValuePlaceholder), []any{cond.Value}

	case clause.OpNotEqual:
		return fmt.Sprintf("(%s != %s)", cond.Field, paramValuePlaceholder), []any{cond.Value}

	case clause.OpGreaterThan:
		return fmt.Sprintf("(%s > %s)", cond.Field, paramValuePlaceholder), []any{cond.Value}

	case clause.OpGreaterEq:
		return fmt.Sprintf("(%s >= %s)", cond.Field, paramValuePlaceholder), []any{cond.Value}

	case clause.OpLessThan:
		return fmt.Sprintf("(%s < %s)", cond.Field, paramValuePlaceholder), []any{cond.Value}

	case clause.OpLessEq:
		return fmt.Sprintf("(%s <= %s)", cond.Field, paramValuePlaceholder), []any{cond.Value}

	case clause.OpIn:
		valueSlice := ToSlice(cond.Value)
		placeholders := GeneratePlaceholdersSlice(
			options.Number,
			len(valueSlice),
			options.Placeholder,
			options.UseNumberedPlaceholder)
		return fmt.Sprintf("(%s IN %s)", cond.Field, placeholders), valueSlice

	case clause.OpNotIn:
		valueSlice := ToSlice(cond.Value)
		placeholders := GeneratePlaceholdersSlice(
			options.Number,
			len(valueSlice),
			options.Placeholder,
			options.UseNumberedPlaceholder,
		)

		return fmt.Sprintf("(%s NOT IN %s)", cond.Field, placeholders), valueSlice

	case clause.OpStartsWith:
		return fmt.Sprintf("(%s LIKE %s)", cond.Field, paramValuePlaceholder), []any{fmt.Sprintf("%s%%", cond.Value)}

	case clause.OpEndsWith:
		return fmt.Sprintf("(%s LIKE %s)", cond.Field, paramValuePlaceholder), []any{fmt.Sprintf("%%%s", cond.Value)}

	case clause.OpContains:
		return fmt.Sprintf("(%s LIKE %s)", cond.Field, paramValuePlaceholder), []any{fmt.Sprintf("%%%s%%", cond.Value)}

	case clause.OpIsNull:
		return fmt.Sprintf("(%s IS NULL)", cond.Field), nil

	case clause.OpNotNull:
		return fmt.Sprintf("(%s IS NOT NULL)", cond.Field), nil

	default:
		return "", []any{cond.Value}
	}
}

func GeneratePlaceholdersSlice(start, count int, placeholder string, useNumbered bool) string {
	if count <= 0 {
		return "()"
	}

	var b strings.Builder
	b.WriteString("(")
	for i := range count {
		currentPlaceholder := placeholder
		if useNumbered {
			currentPlaceholder = fmt.Sprintf("%s%d", placeholder, start+i)
		}
		b.WriteString(currentPlaceholder)
		if i < count-1 {
			b.WriteString(", ")
		}
	}
	b.WriteString(")")
	return b.String()
}

func GenerateSQLSETClause(fields []string, startIndex int, placeholder string, useNumbered bool) string {

	var b strings.Builder
	for i, field := range fields {
		currentPlaceholder := placeholder
		if useNumbered {
			currentPlaceholder = fmt.Sprintf("%s%d", placeholder, startIndex+i)
		}
		fmt.Fprintf(&b, "%s = %s", field, currentPlaceholder)
		if i < len(fields)-1 {
			b.WriteString(", ")
		} else {
			b.WriteString(" ")
		}
	}
	return b.String()
}
