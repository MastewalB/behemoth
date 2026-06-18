package auth

import (
	"context"
	"errors"

	"github.com/MastewalB/behemoth"
	authutils "github.com/MastewalB/behemoth/auth-utils"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/utils"
)

type PasswordAuth struct {
	db          behemoth.Database
	cost        int
	user        behemoth.User
	userFactory func(map[string]any) behemoth.User
}

func NewPasswordAuth(
	cfg behemoth.PasswordConfig,
	user behemoth.User,
	db behemoth.Database,
	userFactory func(map[string]any) behemoth.User,
) *PasswordAuth {
	return &PasswordAuth{
		db:          db,
		cost:        cfg.HashCost,
		user:        user,
		userFactory: userFactory,
	}
}

func (p *PasswordAuth) Login(credentials PasswordCredentials) (behemoth.User, error) {
	ctx := context.Background()

	user, err := models.FindUserByID(ctx, p.db, p.user, credentials.PrimaryKey)

	if err != nil {
		// Compare hash with a password to mitigate timing attacks
		authutils.HashPassword(credentials.Password, p.cost)
		return nil, err
	}

	if authutils.VerifyPassword(user.GetPasswordHash(), credentials.Password) != nil {
		return nil, errors.New("invalid email or password")
	}

	return user, nil
}

func (p *PasswordAuth) Register(data map[string]any) (behemoth.User, error) {

	password := data["password"].(string)
	hashedPassword, err := authutils.HashPassword(password, p.cost)
	if err != nil {
		return nil, err
	}
	data["password_hash"] = hashedPassword
	delete(data, "password")

	data["id"] = utils.GenerateUUID()
	data["email_verified"] = "false"
	data["created_at"] = utils.CurrentTimestamp()
	data["updated_at"] = utils.CurrentTimestamp()
	user := p.userFactory(data)

	created, err := models.CreateUser(context.Background(), p.db, user)
	if err != nil {
		return nil, err
	}

	return created, nil
}

type PasswordCredentials struct {
	PrimaryKey string
	Password   string
}
