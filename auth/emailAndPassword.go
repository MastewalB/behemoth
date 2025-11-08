package auth

import (
	"context"
	"errors"

	"github.com/MastewalB/behemoth"
	authutils "github.com/MastewalB/behemoth/auth-utils"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/utils"
)

type EmailAndPasswordAuth struct {
	db          behemoth.Database
	cost        int
	user        behemoth.User
	userFactory func(map[string]any) behemoth.User
}

func NewEmailAndPasswordAuth(
	cfg behemoth.PasswordConfig,
	user behemoth.User,
	db behemoth.Database,
	userFactory func(map[string]any) behemoth.User,
) *EmailAndPasswordAuth {
	return &EmailAndPasswordAuth{
		db:          db,
		cost:        cfg.HashCost,
		user:        user,
		userFactory: userFactory,
	}
}

func (e *EmailAndPasswordAuth) Login(credentials EmailAndPasswordCredentials) (behemoth.User, error) {
	ctx := context.Background()

	if !utils.IsValidEmail(credentials.Email) {
		return nil, errors.New("invalid email format")
	}

	user, err := models.FindUser(ctx, e.db, e.user, "email", credentials.Email)

	if err != nil {
		// Compare hash with a password to mitigate timing attacks
		authutils.HashPassword(credentials.Password, e.cost)
		return nil, err
	}

	if authutils.VerifyPassword(user.GetPasswordHash(), credentials.Password) != nil {
		return nil, errors.New("invalid email or password")
	}

	return user, nil
}

func (e *EmailAndPasswordAuth) Register(data map[string]any) (behemoth.User, error) {
	email := data["email"].(string)
	if !utils.IsValidEmail(email) {
		return nil, errors.New("invalid email format")
	}

	password := data["password"].(string)
	hashedPassword, err := authutils.HashPassword(password, e.cost)
	if err != nil {
		return nil, err
	}
	data["password_hash"] = hashedPassword
	delete(data, "password")

	data["id"] = utils.GenerateUUID()
	data["email_verified"] = "false"
	data["created_at"] = utils.CurrentTimestamp()
	data["updated_at"] = utils.CurrentTimestamp()

	user := e.userFactory(data)

	created, err := models.CreateUser(context.Background(), e.db, user)
	if err != nil {
		return nil, err
	}

	return created, nil
}

type EmailAndPasswordCredentials struct {
	Email    string
	Password string
}
