package authutils

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

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
	signingMethod jwt.SigningMethod) (jwt.Claims, error) {
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
