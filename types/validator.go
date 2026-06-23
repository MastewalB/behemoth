package types

type Validator interface {
	ValidateEmail(email string) error
	ValidatePassword(password string, options PasswordOptions) error
}
