module example

go 1.26.4

require github.com/MastewalB/behemoth v0.0.0

require (
	github.com/go-chi/chi/v5 v5.2.1
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/oauth2 v0.28.0 // indirect
)

replace github.com/MastewalB/behemoth v0.0.0 => ../
