package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/MastewalB/behemoth/auth"
	"github.com/MastewalB/behemoth/config"
	"github.com/MastewalB/behemoth/storage"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: No .env file found, using system env vars")
	}

	GoogleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	GoogleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	sqliteCfg := &storage.DBConfig{
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: 30 * time.Minute,
	}

	sqliteDB, err := storage.NewSQLiteProvider(":memory:", sqliteCfg)
	if err != nil {
		log.Fatalf("Failed to init SQLite: %v", err)
	}

	cfg := &config.Config{
		Password: config.PasswordConfig{
			DB:       sqliteDB,
			DBConfig: sqliteCfg,
		},
		OAuth: config.OAuthConfig{
			ClientID:     GoogleClientID,
			ClientSecret: GoogleClientSecret,
			RedirectURL:  "http://localhost:8080/callback/google",
			DB:           sqliteDB,
			Scopes:       []string{"email", "profile"},
		},
		JWT:            config.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
		UseDefaultUser: true,
	}
	b := auth.New(cfg)

	// Password endpoints (unchanged)
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		user, err := b.Password.Register(auth.PasswordCredentials{
			Email:    "newuser@example.com",
			Password: "password123",
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Write([]byte("Registered: " + user.GetID()))
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		user, err := b.Password.Authenticate(auth.PasswordCredentials{
			Email:    "newuser@example.com",
			Password: "password123",
		})
		if err != nil {
			http.Error(w, "login failed", http.StatusUnauthorized)
			return
		}
		token, _ := b.JWT.GenerateToken(user)
		w.Write([]byte("Token: " + token))
	})

	// OAuth endpoints
	http.HandleFunc("/login/google", func(w http.ResponseWriter, r *http.Request) {
		state := auth.GenerateState() // Generate a unique state
		url := b.OAuth.AuthURL(state)
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

		user, err := b.OAuth.Authenticate(code)
		if err != nil {
			http.Error(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized)
			return
		}

		token, err := b.JWT.GenerateToken(user)
		if err != nil {
			http.Error(w, "Failed to issue token", http.StatusInternalServerError)
			return
		}
		w.Write([]byte("OAuth Token: " + token))
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
