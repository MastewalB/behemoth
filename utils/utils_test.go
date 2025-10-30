package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateSqlitePlaceholders(t *testing.T) {
	tests := []struct {
		numParams int
		expected  string
	}{
		{0, ""},
		{1, "($1)"},
		{2, "($1, $2)"},
		{3, "($1, $2, $3)"},
		{5, "($1, $2, $3, $4, $5)"},
		{10, "($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.numParams)), func(t *testing.T) {
			result := GenerateSQLPlaceholders(tt.numParams)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateSqliteSETClause(t *testing.T) {
	tests := []struct {
		fields   []string
		expected string
	}{
		{[]string{}, ""},
		{[]string{"name"}, "name = $1 "},
		{[]string{"name", "email"}, "name = $1, email = $2 "},
		{[]string{"name", "email", "age"}, "name = $1, email = $2, age = $3 "},
	}

	for _, tt := range tests {
		t.Run(string(rune(len(tt.fields))), func(t *testing.T) {
			result := GenerateSQLSETClause(tt.fields)
			assert.Equal(t, tt.expected, result)
		})
	}
}
