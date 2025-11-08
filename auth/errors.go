package auth

type BehemothError struct {
	Message string
}

func (e *BehemothError) Error() string {
	return e.Message
}

var (
	ErrInvalidCredentials  = &BehemothError{Message: "invalid credentials"}
	ErrUserNotFound        = &BehemothError{Message: "user not found"}
	ErrEmailAlreadyUsed    = &BehemothError{Message: "email already in use"}
	ErrUsernameAlreadyUsed = &BehemothError{Message: "username already in use"}
)

var (
	ErrInvalidEmail           = &BehemothError{Message: "invalid email"}
	ErrInvalidPassword        = &BehemothError{Message: "invalid password"}
	ErrInvalidEmailOrPassword = &BehemothError{Message: "invalid email or password"}
	ErrInvalidToken           = &BehemothError{Message: "invalid token"}
	ErrPasswordTooShort       = &BehemothError{Message: "password too short"}
	ErrPasswordTooLong        = &BehemothError{Message: "password too long"}
)
