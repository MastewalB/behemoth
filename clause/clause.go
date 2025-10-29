package clause

type Operator string

const (
	OpEqual       Operator = "eq"
	OpNotEqual    Operator = "ne"
	OpGreaterThan Operator = "gt"
	OpGreaterEq   Operator = "ge"
	OpLessThan    Operator = "lt"
	OpLessEq      Operator = "le"
	OpIn          Operator = "in"
	OpNotIn       Operator = "nin"
	OpContains    Operator = "contains"
	OpStartsWith  Operator = "starts_with"
	OpEndsWith    Operator = "ends_with"
	OpIsNull      Operator = "null"
	OpNotNull     Operator = "not_null"
)

type Condition struct {
	Field    string
	Operator Operator
	Value    any
}

type Logic string

const (
	OpAnd Logic = "AND"
	OpOr  Logic = "OR"
)

type Expression struct {
	Logic      Logic
	Conditions []Condition
	Children   []*Expression
}
