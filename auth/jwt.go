package auth

import (
	"errors"
	"time"

	"github.com/MastewalB/behemoth/config"
	"github.com/MastewalB/behemoth/models"
	"github.com/golang-jwt/jwt/v5"
)

type JWTService struct {
	secret string
	expiry time.Duration
}

func NewJWTService(cfg config.JWTConfig) *JWTService {
	return &JWTService{
		secret: cfg.Secret,
		expiry: cfg.Expiry,
	}
}

func (j *JWTService) GenerateToken(user models.User) (string, error) {
	claims := jwt.MapClaims{
		"id":  user.GetID(),
		"exp": time.Now().Add(j.expiry).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.secret))
}

func (j *JWTService) ValidateToken(tokenStr string) (models.User, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte(j.secret), nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}
	id, _ := claims["id"].(string)
	return &models.DefaultUser{ID: id}, nil
}
