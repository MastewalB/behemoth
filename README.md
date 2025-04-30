# Behemoth
## Authentication Library for Golang

Behemoth is a flexible authentication library for Go applications. It simplifies adding common authentication strategies like password-based login and OAuth 2.0 with JWT or Sessions. It handles user registration, authentication, and management, with various database integrations like Postgres and SQLite through a configurable interface. Behemoth provides a basic User Model with full built in CRUD features. It’s also compatible with custom user models and supports additional OAuth providers.




## Installation

```bash
$ go get github.com/MastewalB/behemoth
```


## Supported Databases
* PostgreSQL
* SQLite


## Examples
Create a Behemoth instance with built-in User Model. 

```go
import (
    "github.com/MastewalB/behemoth"
    "github.com/MastewalB/behemoth/models"
)

// Custom providers can be added to this list
oauthProviders := []behemoth.Provider{
		providers.NewGoogle(
			"GoogleClientID",
			"GoogleClientSecret",
			"GoogleRedirectURL",
			"email", "profile",
		),
		providers.NewFacebook(
			"FBClientID",
			"FBClientSecret",
			"FBRedirectURL",
			"email", "public_profile",
		),
	}

func main() {
	pgCfg := &behemoth.Config[*models.User]{
		DatabaseConfig: behemoth.DatabaseConfig[*models.User]{
			Name:           behemoth.Postgres,
			DB:             pg,
			UseDefaultUser: true,
		},
		Password:       &behemoth.PasswordConfig{HashCost: 10},
		OAuthProviders: oauthProviders,
		JWT:            &behemoth.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
		UseSessions:    true,
		Session: &behemoth.SessionConfig{
			CookieName: "session_id",
			Expiry:     2 * time.Hour,
			Factory: func(id string) behemoth.Session {
				return behemoth.NewDefaultSession(id, time.Hour)
			},
		},
	}
	
	behemoth, err := auth.New(config)

}

```
Check [examples](https://github.com/MastewalB/behemoth/tree/main/examples) for a demo application using PostgreSQL and SQLite.

Clone the repo and create `.env` file containing the client credentials for the providers used in `examples/main.go`.

```bash
$ cd examples/
$ go run main.go
```
Open http://localhost:8080 in your browser.


## Supported Providers
* Google
* Facebook
* Github
* Apple
* Amazon

Custom providers can be added by implementing the `Provider` interface.

## User Models

## JWT 
The JWTService type is responsible for handling JSON Web Token operations. It uses the `golang-jwt` package to sign and validate tokens. Tokens can be configured through the `JWTConfig` struct

```go
import "github.com/golang-jwt/jwt/v5"

type JWTConfig struct {
	Secret        string
	Expiry        time.Duration
	SigningMethod jwt.SigningMethod
	Claims        jwt.Claims
}
```

By default tokens are signed with `jwt.SigningMethodHS256`. JWT tokens will be used as default authentication method if Sessions are not configured explicitly. Claims can be customized as long as they implement the `jwt.Claims` interface.
## Session

## Upcoming Features

* Revocable JWT Tokens
* Support for Gin and Echo routers