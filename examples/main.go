package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/auth"
	"github.com/MastewalB/behemoth/providers"
	"github.com/MastewalB/behemoth/storage"
	"github.com/MastewalB/behemoth/utils"
	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: No .env file found, using system env vars")
	}

	GoogleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	GoogleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	GoogleRedirectURL := os.Getenv("GOOGLE_REDIRECT_URL")
	FBClientID := os.Getenv("FACEBOOK_CLIENT_ID")
	FBClientSecret := os.Getenv("FACEBOOK_CLIENT_SECRET")
	FBRedirectURL := os.Getenv("FACEBOOK_REDIRECT_URL")
	PG_HOST := os.Getenv("PG_HOST")
	PG_PORT := os.Getenv("PG_PORT")
	PG_USER := os.Getenv("PG_USER")
	PG_PASSWORD := os.Getenv("PG_PASSWORD")
	PG_DATABASE := os.Getenv("PG_DATABASE")

	// Connection string format:
	// "postgres://username:password@host:port/database?sslmode=disable"
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", PG_USER, PG_PASSWORD, PG_HOST, PG_PORT, PG_DATABASE)
	pg, pgerr := sql.Open("postgres", connStr)
	if pgerr != nil {
		log.Printf("Failed to initialize Postgres db: %v", err)
	}

	_, err = pg.Exec("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE, username TEXT UNIQUE, firstname TEXT, lastname TEXT, password_hash TEXT)")
	if err != nil {
		log.Fatalf("Failed to initialize Postgres db: %v", err)
	}

	// Memory - file:main?mode=memory&cache=shared
	db, err := sql.Open("sqlite3", "localsqlite.db")
	if err != nil {
		log.Fatalf("Failed to initialize SQLite db: %v", err)
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE, username TEXT UNIQUE, firstname TEXT, lastname TEXT, password_hash TEXT)")
	if err != nil {
		log.Fatalf("Failed to initialize SQLite db: %v", err)
	}

	if err != nil {
		log.Fatalf("Failed to init SQLite: %v", err)
	}

	oauthProviders := []behemoth.Provider{
		providers.NewGoogle(
			GoogleClientID,
			GoogleClientSecret,
			GoogleRedirectURL,
			"email", "profile",
		),
		providers.NewFacebook(
			FBClientID,
			FBClientSecret,
			FBRedirectURL,
			"email", "public_profile",
		),
		// Add more providers later, e.g., "facebook"
	}

	pgCfg := &behemoth.Config[*behemoth.DefaultUser]{
		Password:       &behemoth.PasswordConfig{HashCost: 10},
		OAuthProviders: oauthProviders,
		JWT:            &behemoth.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
		UseDefaultUser: true,
		DB:             &storage.Postgres[*behemoth.DefaultUser]{DB: pg, PK: "id", Table: "users"},
		UserModel:      &behemoth.DefaultUser{},
	}
	bpg := auth.New(pgCfg)

	cfg := &behemoth.Config[*behemoth.DefaultUser]{
		Password:       &behemoth.PasswordConfig{HashCost: 10},
		OAuthProviders: oauthProviders,
		JWT:            &behemoth.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
		UseDefaultUser: true,
		DB:             &storage.SQLlite[*behemoth.DefaultUser]{DB: db, PK: "id", Table: "users"},
		UserModel:      &behemoth.DefaultUser{},
	}
	bsql := auth.New(cfg)

	router := chi.NewRouter()

	// Password endpoints
	var user *behemoth.DefaultUser
	router.Get("/register", func(w http.ResponseWriter, r *http.Request) {
		user, err = bsql.Password.Create("newuser@example.com", "username", "firstname", "lastname", "password123")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Write([]byte("Registered: " + user.GetID()))
	})

	router.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		if user == nil {
			http.Error(w, "Please register first", http.StatusBadRequest)
			return
		}
		user, err := bsql.Password.Authenticate(auth.PasswordCredentials{
			PK:       user.GetID(),
			Password: "password123",
		})
		if err != nil {
			log.Println(err.Error())
			http.Error(w, "login failed", http.StatusUnauthorized)
			return
		}
		token, _ := bsql.JWT.GenerateToken(user)
		w.Write([]byte("Token: " + token))
	})

	var pguser *behemoth.DefaultUser
	router.Get("/pg/register", func(w http.ResponseWriter, r *http.Request) {
		if pgerr != nil {
			http.Error(w, "Couldn't connect to PG database", http.StatusBadRequest)
			return
		}
		log.Printf("Received /pg/register request")
		email := fmt.Sprintf("newuser%d@example.com", time.Now().UnixNano())
		username := fmt.Sprintf("username%d", time.Now().UnixNano())
		log.Printf("Registering: email=%s, username=%s", email, username)
		pguser, err = bpg.Password.Create(email, username, "firstname", "lastname", "password123")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Write([]byte("Registered: " + pguser.GetID()))
	})

	router.Get("/pg/login", func(w http.ResponseWriter, r *http.Request) {
		if pgerr != nil {
			http.Error(w, "Couldn't connect to PG database", http.StatusBadRequest)
			return
		}
		if pguser == nil {
			http.Error(w, "Please register first", http.StatusBadRequest)
			return
		}
		pguser, err := bpg.Password.Authenticate(auth.PasswordCredentials{
			PK:       pguser.GetID(),
			Password: "password123",
		})
		if err != nil {
			log.Println(err.Error())
			http.Error(w, "login failed", http.StatusUnauthorized)
			return
		}
		token, _ := bsql.JWT.GenerateToken(pguser)
		w.Write([]byte("Token: " + token))
	})

	// OAuth endpoints
	router.Get("/login/{provider}", func(w http.ResponseWriter, r *http.Request) {
		state := utils.GenerateState() // Generate a unique state
		url, _ := bsql.OAuth.AuthURL(r, state)
		// Store state in a cookie for validation (simplified for demo)
		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state",
			Value:    state,
			Expires:  time.Now().Add(10 * time.Minute),
			HttpOnly: true,
			Path:     "/",
			Domain:   "localhost",
		})
		log.Printf("Setting oauth_state cookie: %s", state)
		log.Printf("Auth URL - %s", url)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	})

	router.Get("/callback/{provider}", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Callback request: Host=%s, URL=%s", r.Host, r.URL.String())
		log.Printf("Cookies in request: %v", r.Cookies())

		providerName := chi.URLParam(r, "provider")
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Missing authorization code", http.StatusBadRequest)
			return
		}

		state := r.URL.Query().Get("state")
		cookie, err := r.Cookie("oauth_state")
		if err != nil {
			log.Printf("Cookie error: %v, State: %s", err, state)
			http.Error(w, "State validation failed: cookie not found", http.StatusUnauthorized)
			return
		}
		if cookie.Value != state {
			log.Printf("State mismatch: cookie=%s, state=%s", cookie.Value, state)
			http.Error(w, "Invalid state parameter", http.StatusUnauthorized)
			return
		}

		user, err := bsql.OAuth.Authenticate(providerName, code)
		if err != nil {
			http.Error(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized)
			return
		}

		token, err := bsql.JWT.GenerateToken(user)
		if err != nil {
			http.Error(w, "Failed to issue token", http.StatusInternalServerError)
			return
		}
		w.Write([]byte("OAuth Token: " + token))
	})

	func(routes []chi.Route) {
		for _, r := range routes {
			log.Println(r.Pattern)
		}
	}(router.Routes())
	log.Println("Started Server on port 8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}
