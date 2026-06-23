package core

import "golang.org/x/crypto/bcrypt"

type PasswordHasher interface {
	Hash(password string) (string, error)

	Verify(password, hash string) bool
}

type BcryptHasher struct {
	Cost int
}

func (h *BcryptHasher) Hash(password string) (string, error) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), h.Cost)
	if err != nil {
		return "", err
	}

	return string(passwordHash), nil
}

func (h *BcryptHasher) Verify(password, hash string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(password), []byte(hash)); err != nil {
		return false
	}
	return true
}
