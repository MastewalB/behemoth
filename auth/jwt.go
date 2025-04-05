package auth

import (
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/golang-jwt/jwt/v5"
)

type JWTService struct {
	secret        string
	expiry        time.Duration
	signingMethod jwt.SigningMethod
	jwtClaim      jwt.Claims
}

func NewJWTService(cfg behemoth.JWTConfig) *JWTService {
	var claim jwt.Claims = &DefaultJWTClaims{}
	var signingMethod jwt.SigningMethod = jwt.SigningMethodHS256

	if cfg.SigningMethod != nil {
		signingMethod = cfg.SigningMethod
	}
	if cfg.Claims != nil {
		claim = cfg.Claims
	}
	return &JWTService{
		secret:        cfg.Secret,
		expiry:        cfg.Expiry,
		signingMethod: signingMethod,
		jwtClaim:      claim,
	}
}

func (j *JWTService) GenerateToken(user behemoth.User) (string, error) {
	claims := reflect.New(
		reflect.TypeOf(j.jwtClaim).Elem(),
	).Interface().(jwt.Claims)

	if claims == nil {
		return "", errors.New("claims cannot be nil")
	}

	switch c := claims.(type) {
	case *DefaultJWTClaims:
		c.ID = user.GetID()
		c.RegisteredClaims = jwt.RegisteredClaims{
			Issuer:    user.GetID(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		}
	case jwt.MapClaims:
		c["id"] = user.GetID()
		c["exp"] = time.Now().Add(j.expiry).Unix()
	}

	token := jwt.NewWithClaims(j.signingMethod, claims)
	signedToken, err := token.SignedString([]byte(j.secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

func (j *JWTService) ValidateToken(tokenStr string) (jwt.Claims, error) {
	claims := reflect.New(
		reflect.TypeOf(j.jwtClaim).Elem(),
	).Interface().(jwt.Claims)

	token, err := jwt.ParseWithClaims(
		tokenStr,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method.Alg() != j.signingMethod.Alg() {
				return nil, fmt.Errorf("unexpected signing method: \nwant: %v\ngot: %v",
					j.signingMethod.Alg(), token.Header["alg"])
			}
			return []byte(j.secret), nil
		})

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return token.Claims, nil
}

type DefaultJWTClaims struct {
	ID string `json:"id"`
	jwt.RegisteredClaims
}
