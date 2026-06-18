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
		{-1, "()"},
		{1, "($1)"},
		{2, "($1, $2)"},
		{3, "($1, $2, $3)"},
		{5, "($1, $2, $3, $4, $5)"},
		{10, "($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.numParams)), func(t *testing.T) {
			result := GenerateSQLPlaceholders(1, 1+tt.numParams-1)
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

func TestIsValidEmail(t *testing.T) {
	emailTests := []struct {
		email    string
		expected bool
	}{
		{"valid@valid.com", true},
		{"validmail@email.com", true},
		{"invalid.com", false},
		{"@nouser.com", false},
		{"noat.com", false},
		{"user@.com", false},
		{"user@domain", false},
		{"user@domain.c", false},
		{"user@domain..com", false},
		{"user@.domain.com", false},
		{"", false},
	}

	for _, tt := range emailTests {
		t.Run(tt.email, func(t *testing.T) {
			result := IsValidEmail(tt.email)
			assert.Equal(t, tt.expected, result)
		})
	}
}
