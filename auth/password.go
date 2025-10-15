package auth

import (
	"context"
	"errors"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
	"golang.org/x/crypto/bcrypt"
)

type PasswordAuth struct {
	db             behemoth.Database
	jwtSvc         *JWTService
	cost           int
	useDefaultUser bool
	user           behemoth.User
}

func NewPasswordAuth(cfg behemoth.PasswordConfig,
	jwtSvc *JWTService,
	useDefaultUser bool,
	user behemoth.User,
	db behemoth.Database,
) *PasswordAuth {
	return &PasswordAuth{
		db:             db,
		jwtSvc:         jwtSvc,
		cost:           cfg.HashCost,
		useDefaultUser: useDefaultUser,
		user:           user,
	}
}

func (p *PasswordAuth) Authenticate(credentials any) (behemoth.User, error) {
	ctx := context.Background()
	pc, ok := credentials.(PasswordCredentials)
	if !ok {
		return nil, errors.New("invalid credentials")
	}
	user, err := models.FindUserByID(ctx, p.db, p.user, pc.PrimaryKey)

	if err != nil {
		return nil, err
	}

	if bcrypt.CompareHashAndPassword([]byte(user.GetPasswordHash()), []byte(pc.Password)) != nil {
		return nil, errors.New("invalid email or password")
	}

	// if p.useDefaultUser {
	// 	defaultUser, ok := any(user).(*models.User)
	// 	if !ok {
	// 		return nil, errors.New("expected DefaultUser when UseDefaultUser is true")
	// 	}
	// 	return defaultUser, nil
	// }

	return user, nil
}

func (p *PasswordAuth) Create(
	email string,
	username string,
	firstname string,
	lastname string,
	password string,
) (*models.User, error) {
	if !p.useDefaultUser {
		return nil, errors.New("registration not supported for custom models")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), p.cost)
	if err != nil {
		return nil, err
	}
	user := &models.User{
		Email:        email,
		Username:     username,
		Firstname:    firstname,
		Lastname:     lastname,
		PasswordHash: string(hash),
	}

	created, err := models.CreateUser(context.Background(), p.db, user)
	if err != nil {
		return nil, err
	}

	return created.(*models.User), nil
}

type PasswordCredentials struct {
	PrimaryKey string
	Password   string
}
