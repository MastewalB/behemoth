package auth

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/MastewalB/behemoth"
	authutils "github.com/MastewalB/behemoth/auth-utils"
	"github.com/golang-jwt/jwt/v5"
)

type JWTManager struct {
	secret        string
	expiry        time.Duration
	signingMethod jwt.SigningMethod
	jwtClaim      jwt.Claims
}

func NewJWTManager(cfg behemoth.JWTConfig) *JWTManager {
	var claim jwt.Claims = &DefaultJWTClaims{}
	var signingMethod jwt.SigningMethod = jwt.SigningMethodHS256

	if cfg.SigningMethod != nil {
		signingMethod = cfg.SigningMethod
	}
	if cfg.Claims != nil {
		claim = cfg.Claims
	}
	return &JWTManager{
		secret:        cfg.Secret,
		expiry:        cfg.Expiry,
		signingMethod: signingMethod,
		jwtClaim:      claim,
	}
}

func (j *JWTManager) Create(ctx context.Context, userID string) (string, error) {
	claims := reflect.New(
		reflect.TypeOf(j.jwtClaim).Elem(),
	).Interface().(jwt.Claims)

	if claims == nil {
		return "", errors.New("claims cannot be nil")
	}

	claim := claims.(*DefaultJWTClaims)
	claim.ID = userID

	signedToken, err := authutils.GenerateToken(claim, j.signingMethod, j.secret)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func (j *JWTManager) Validate(ctx context.Context, tokenStr string) (any, error) {
	claims := reflect.New(
		reflect.TypeOf(j.jwtClaim).Elem(),
	).Interface().(jwt.Claims)

	claim := claims.(*DefaultJWTClaims)
	tokenClaim, err := authutils.VerifyToken(tokenStr, claim, j.secret, j.signingMethod)

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	return tokenClaim, nil
}

func (j *JWTManager) Revoke(ctx context.Context, tokenStr string) error {
	return errors.New("token revocation not available")
}

type DefaultJWTClaims struct {
	ID string `json:"id"`
	jwt.RegisteredClaims
}
