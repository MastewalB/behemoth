package middleware

import (
	"net/http"

	"github.com/MastewalB/behemoth/auth"
)

func Authenticate(jwtSvc *auth.JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			if token == "" {
				http.Error(w, "missing token", http.StatusUnauthorized)
				return
			}
			_, err := jwtSvc.ValidateToken(token)
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			// Add user to context or proceed
			next.ServeHTTP(w, r)
		})
	}
}
