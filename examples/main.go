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
	"github.com/MastewalB/behemoth/storage"
	"github.com/MastewalB/behemoth/utils"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: No .env file found, using system env vars")
	}

	GoogleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	GoogleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	PG_HOST := os.Getenv("PG_HOST")
	PG_PORT := os.Getenv("PG_PORT")
	PG_USER := os.Getenv("PG_USER")
	PG_PASSWORD := os.Getenv("PG_PASSWORD")
	PG_DATABASE := os.Getenv("PG_DATABASE")

	// Connection string format:
	// "postgres://username:password@host:port/database?sslmode=disable"
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", PG_USER, PG_PASSWORD, PG_HOST, PG_PORT, PG_DATABASE)
	fmt.Println(connStr)
	pg, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to initialize Postgres db: %v", err)
	}

	_, err = pg.Exec("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE, username TEXT UNIQUE, firstname TEXT, lastname TEXT, password_hash TEXT)")
	if err != nil {
		log.Fatalf("Failed to initialize Postgres db: %v", err)
	}

	db, err := sql.Open("sqlite3", "file:main?mode=memory&cache=shared")
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

	pgCfg := &behemoth.Config[*behemoth.DefaultUser]{
		Password: &behemoth.PasswordConfig{HashCost: 10},
		OAuth: &behemoth.OAuthConfig{
			ClientID:     GoogleClientID,
			ClientSecret: GoogleClientSecret,
			RedirectURL:  "http://localhost:8080/callback/google",
			Scopes:       []string{"email", "profile"},
		},
		JWT:            &behemoth.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
		UseDefaultUser: true,
		DB:             &storage.Postgres[*behemoth.DefaultUser]{DB: pg, PK: "id", Table: "users"},
		UserModel:      &behemoth.DefaultUser{},
	}
	bpg := auth.New(pgCfg)

	cfg := &behemoth.Config[*behemoth.DefaultUser]{
		Password: &behemoth.PasswordConfig{HashCost: 10},
		OAuth: &behemoth.OAuthConfig{
			ClientID:     GoogleClientID,
			ClientSecret: GoogleClientSecret,
			RedirectURL:  "http://localhost:8080/callback/google",
			Scopes:       []string{"email", "profile"},
		},
		JWT:            &behemoth.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
		UseDefaultUser: true,
		DB:             &storage.SQLlite[*behemoth.DefaultUser]{DB: db, PK: "id", Table: "users"},
		UserModel:      &behemoth.DefaultUser{},
	}
	bsql := auth.New(cfg)

	// Password endpoints
	var user *behemoth.DefaultUser
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		user, err = bsql.Password.Create("newuser@example.com", "username", "firstname", "lastname", "password123")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Write([]byte("Registered: " + user.GetID()))
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
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
	http.HandleFunc("/pg/register", func(w http.ResponseWriter, r *http.Request) {
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

	http.HandleFunc("/pg/login", func(w http.ResponseWriter, r *http.Request) {
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
	http.HandleFunc("/login/google", func(w http.ResponseWriter, r *http.Request) {
		state := utils.GenerateState() // Generate a unique state
		url := bsql.OAuth.AuthURL(state)
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
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	})

	http.HandleFunc("/callback/google", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Callback request: Host=%s, URL=%s", r.Host, r.URL.String())
		log.Printf("Cookies in request: %v", r.Cookies())

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

		user, err := bsql.OAuth.Authenticate(code)
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

	log.Fatal(http.ListenAndServe(":8080", nil))
}
