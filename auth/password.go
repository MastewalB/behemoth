package auth

import (
	"errors"

	"github.com/MastewalB/behemoth/config"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/storage"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type PasswordAuth struct {
	db             storage.DatabaseProvider
	jwtSvc         *JWTService
	cost           int
	useDefaultUser bool
}

func NewPasswordAuth(cfg config.PasswordConfig, jwtSvc *JWTService) *PasswordAuth {
	return &PasswordAuth{
		db:             cfg.DB,
		jwtSvc:         jwtSvc,
		cost:           cfg.HashCost,
		useDefaultUser: cfg.UseDefaultUser,
	}
}

func (p *PasswordAuth) Authenticate(credentials any) (models.User, error) {
	pc, ok := credentials.(PasswordCredentials)
	if !ok {
		return nil, errors.New("invalid credentials")
	}
	user, err := p.db.FindUserByEmail(pc.Email)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(user.GetPasswordHash()), []byte(pc.Password)) != nil {
		return nil, errors.New("invalid email or password")
	}
	return user, nil
}

func (p *PasswordAuth) Register(credentials any) (models.User, error) {
	if !p.useDefaultUser {
		return nil, errors.New("registration not supported for custom models")
	}
	pc, ok := credentials.(PasswordCredentials)
	if !ok {
		return nil, errors.New("invalid credentials")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pc.Password), p.cost)
	if err != nil {
		return nil, err
	}
	user := &models.DefaultUser{
		ID:           generateUUID(),
		Email:        pc.Email,
		PasswordHash: string(hash),
	}
	return user, p.db.SaveUser(user)
}

type PasswordCredentials struct {
	Email    string
	Password string
}

func generateUUID() string {
	return uuid.New().String()
}
