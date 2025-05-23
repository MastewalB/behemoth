package auth

import (
	"errors"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
	"golang.org/x/crypto/bcrypt"
)

type PasswordAuth[T behemoth.User] struct {
	db             behemoth.Database[T]
	jwtSvc         *JWTService
	cost           int
	useDefaultUser bool
}

func NewPasswordAuth[T behemoth.User](cfg behemoth.PasswordConfig,
	jwtSvc *JWTService,
	useDefaultUser bool,
	user behemoth.User,
	db behemoth.Database[T],
) *PasswordAuth[T] {
	return &PasswordAuth[T]{
		db:             db,
		jwtSvc:         jwtSvc,
		cost:           cfg.HashCost,
		useDefaultUser: useDefaultUser,
	}
}

func (p *PasswordAuth[T]) Authenticate(credentials any) (behemoth.User, error) {
	pc, ok := credentials.(PasswordCredentials)
	if !ok {
		return nil, errors.New("invalid credentials")
	}
	user, err := p.db.FindByPK(pc.PrimaryKey)

	if err != nil {
		return nil, err
	}

	if bcrypt.CompareHashAndPassword([]byte(user.GetPasswordHash()), []byte(pc.Password)) != nil {
		return nil, errors.New("invalid email or password")
	}

	if p.useDefaultUser {
		defaultUser, ok := any(user).(*models.User)
		if !ok {
			return nil, errors.New("expected DefaultUser when UseDefaultUser is true")
		}
		return defaultUser, nil
	}

	return user, nil
}

func (p *PasswordAuth[T]) Create(
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
	return p.db.SaveUser(user)
}

type PasswordCredentials struct {
	PrimaryKey string
	Password   string
}
