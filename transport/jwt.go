package transport

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/MastewalB/behemoth"
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

	signedToken, err := GenerateToken(claim, j.signingMethod, j.secret)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func (j *JWTManager) Verify(ctx context.Context, tokenStr string) (any, error) {
	claims := reflect.New(
		reflect.TypeOf(j.jwtClaim).Elem(),
	).Interface().(jwt.Claims)

	claim := claims.(*DefaultJWTClaims)
	tokenClaim, err := VerifyToken(tokenStr, claim, j.secret, j.signingMethod)

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	return tokenClaim, nil
}

func (j *JWTManager) Revoke(ctx context.Context, tokenStr string) error {
	return errors.New("token revocation not available")
}

func (j *JWTManager) TokenType() behemoth.TokenType {
	return behemoth.TokenTypeBearer
}

type DefaultJWTClaims struct {
	ID string `json:"id"`
	jwt.RegisteredClaims
}

func GenerateToken(
	claim jwt.Claims,
	signingMethod jwt.SigningMethod,
	secret string) (string, error) {

	token := jwt.NewWithClaims(signingMethod, claim)
	signedToken, err := token.SignedString([]byte(secret))

	if err != nil {
		return "", errors.New("failed to sign token: " + err.Error())
	}

	return signedToken, nil
}

func VerifyToken(
	tokenString string,
	claim jwt.Claims,
	secret string,
	signingMethod jwt.SigningMethod,
) (jwt.Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		claim,
		func(token *jwt.Token) (any, error) {
			if token.Method.Alg() != signingMethod.Alg() {
				return nil, errors.New("unexpected signing method: " + token.Header["alg"].(string))
			}
			return []byte(secret), nil
		})

	if err != nil {
		return nil, errors.New("failed to parse token: " + err.Error())
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return token.Claims, nil
}
