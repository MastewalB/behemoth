package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

func GenerateRandomString(length int) string {
	// Calculate the required byte length to produce the desired string length
	// Base64 encodes 3 bytes into 4 characters, so we need 3/4 of the length in bytes
	byteLength := (length * 3) / 4
	if byteLength <= 0 {
		byteLength = 1
	}

	// Generate random bytes
	randomBytes := make([]byte, byteLength)
	rand.Read(randomBytes)

	// Encode to URL-safe base64 (without padding)
	randomString := base64.RawURLEncoding.EncodeToString(randomBytes)

	// Trim to exact length if needed (though base64 length is predictable)
	if len(randomString) > length {
		randomString = randomString[:length]
	}

	return randomString
}

func GenerateUUID() string {
	return uuid.New().String()
}

func GenerateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func GenerateSQLPlaceholders(begin, end int) string {
	if end < begin {
		return "()"
	}

	var b strings.Builder
	b.WriteString("(")
	for i := begin; i <= end; i++ {
		b.WriteString(fmt.Sprintf("$%d", i))
		if i < end {
			b.WriteString(", ")
		}
	}
	b.WriteString(")")
	return b.String()
}

func GenerateSQLSETClause(fields []string) string {

	var b strings.Builder
	for i, field := range fields {
		b.WriteString(fmt.Sprintf("%s = $%d", field, i+1))
		if i < len(fields)-1 {
			b.WriteString(", ")
		} else {
			b.WriteString(" ")
		}
	}

	return b.String()
}

func CurrentTimestamp() string {
	return fmt.Sprintf("%d", (int64)(time.Now().Unix()))
}

func IsValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func NewTypeAssertionError(expectedType string, actualValue any) error {
	return fmt.Errorf("type assertion failed: expected %s, got %T", expectedType, actualValue)
}

func MapToSlice[T comparable, U any](m map[T]U) ([]T, []U) {
	keys := make([]T, 0, len(m))
	values := make([]U, 0, len(m))

	for k, v := range m {
		keys = append(keys, k)
		values = append(values, v)
	}

	return keys, values
}
