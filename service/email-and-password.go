package service

import (
	"context"
	"errors"
	"strings"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/types"
)

type EmailAndPasswordService struct {
	authContext types.AuthContext
}

func NewEmailAndPasswordService(
	authContext types.AuthContext,
) *EmailAndPasswordService {
	return &EmailAndPasswordService{
		authContext: authContext,
	}
}

func (eps *EmailAndPasswordService) SignUp(ctx context.Context, userData behemoth.M) (behemoth.User, error) {
	emailStr, ok := userData["email"].(string)
	if !ok {
		return nil, errors.New("invalid email")
	}

	email := strings.ToLower(strings.TrimSpace(emailStr))

	err := eps.authContext.Validator.ValidateEmail(email)
	if err != nil {
		return nil, errors.New("invalid email")
	}

	password := userData["password"].(string)
	err = eps.authContext.Validator.ValidatePassword(password, eps.authContext.PasswordOptions)
	if err != nil {
		return nil, errors.New("invalid password")
	}

	_, err = eps.authContext.InternalAdapter.FindUserByEmail(ctx, eps.authContext.User, email)
	if err == nil {
		// Hash password to mitigate timing attacks
		eps.authContext.PasswordOptions.PasswordHasher.Hash(password)
		return nil, errors.New("user already exists")
	}

	passwordHash, err := eps.authContext.PasswordOptions.PasswordHasher.Hash(password)
	if err != nil {
		return nil, err
	}

	userData["password_hash"] = passwordHash
	userData["email_verified"] = false

	user, err := eps.authContext.InternalAdapter.CreateUser(ctx, eps.authContext.User, userData)
	if err != nil {
		return nil, errors.New("user create failed")
	}

	return user, nil
}

func (eps *EmailAndPasswordService) SignIn(ctx context.Context, credentials EmailAndPasswordCredentials) (behemoth.User, error) {

	email := strings.ToLower(strings.TrimSpace(credentials.Email))

	user, err := eps.authContext.InternalAdapter.FindUserByEmail(ctx, eps.authContext.User, email)
	if err != nil {
		// Compare hash with a password to mitigate timing attacks
		eps.authContext.PasswordOptions.PasswordHasher.Hash(credentials.Password)
		return nil, err
	}

	if !eps.authContext.PasswordOptions.PasswordHasher.Verify(user.GetPasswordHash(), credentials.Password) {
		return nil, errors.New("invalid email or password")
	}

	return user, nil

}

func (eps *EmailAndPasswordService) SignOut(ctx context.Context) {}

type EmailAndPasswordCredentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
