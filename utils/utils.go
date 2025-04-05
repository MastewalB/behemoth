package utils

import (
	"crypto/rand"
	"encoding/base64"

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
