package core

// type BcryptHasher struct {
// 	Cost int
// }

// func (h *BcryptHasher) Hash(password string) (string, error) {
// 	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), h.Cost)
// 	if err != nil {
// 		return "", err
// 	}

// 	return string(passwordHash), nil
// }

// func (h *BcryptHasher) Verify(password, hash string) (bool, error) {
// 	if err := bcrypt.CompareHashAndPassword([]byte(password), []byte(hash)); err != nil {
// 		return false, nil
// 	}
// 	return true, nil
// }
