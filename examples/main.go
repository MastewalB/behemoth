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
	"github.com/MastewalB/behemoth/models"
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

	pgCfg := &behemoth.Config[*models.User]{
		Password:       &behemoth.PasswordConfig{HashCost: 10},
		OAuthProviders: oauthProviders,
		JWT:            &behemoth.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
		UseDefaultUser: true,
		DB:             &storage.Postgres[*models.User]{DB: pg, PK: "id", Table: "users"},
		UserModel:      &models.User{},
	}
	bpg := auth.New(pgCfg)

	sqliteProvider, err := storage.NewSQLite[*models.User](db, "users", "id", func(id string) behemoth.Session {
		return behemoth.NewDefaultSession(id, time.Hour)
	})
	if err != nil {
		log.Fatalf("Failed to init SQLite: %v", err)
	}

	cfg := &behemoth.Config[*models.User]{
		Password:       &behemoth.PasswordConfig{HashCost: 10},
		OAuthProviders: oauthProviders,
		JWT:            &behemoth.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
		UseDefaultUser: true,
		DB:             sqliteProvider,
		UserModel:      &models.User{},
		UseSessions:    true,
	}
	bsql := auth.New(cfg)

	router := chi.NewRouter()

	// Password endpoints
	var user *models.User
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
			user, err = bsql.DB.FindByPK("a797fd46-7ff5-411a-b8bf-843092ee6e68")
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
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

		if bsql.UseSessions {
			session, err := bsql.Session.CreateSession()
			if err != nil {
				log.Println("Failed to create session:", err.Error())
				http.Error(w, "Failed to create session", http.StatusInternalServerError)
				return
			}

			if err := session.Set("user_id", user.GetID()); err != nil {
				log.Println("Failed to set user_id in session:", err.Error())
				http.Error(w, "Failed to set session data", http.StatusInternalServerError)
				return
			}

			// Access email by casting to DefaultUser if UseDefaultUser is true

			defaultUser, ok := user.(*models.User)
			if !ok {
				log.Println("Expected DefaultUser when UseDefaultUser is true")
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			} else {
				if err := session.Set("email", defaultUser.Email); err != nil {
					log.Println("Failed to set email in session:", err.Error())
					http.Error(w, "Failed to set session data", http.StatusInternalServerError)
					return
				}
			}

			if _, err := bsql.Session.UpdateSession(session); err != nil {
				log.Println("Failed to save session:", err.Error())
				http.Error(w, "Failed to save session", http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name:     "session_id", // Matches SessionManager's cookieName
				Value:    session.SessionID(),
				Path:     "/",
				HttpOnly: true,                                 // Prevents JavaScript access
				Secure:   true,                                 // Requires HTTPS
				SameSite: http.SameSiteStrictMode,              // Mitigates CSRF
				MaxAge:   int(bsql.Session.Expiry().Seconds()), // Matches session expiry
			})

			w.Write([]byte("Login successful, session created"))
		} else {
			// Fallback to JWT if sessions are not enabled
			token, err := bsql.JWT.GenerateToken(user)
			if err != nil {
				log.Println("Failed to generate token:", err.Error())
				http.Error(w, "Failed to generate token", http.StatusInternalServerError)
				return
			}
			w.Write([]byte("Token: " + token))
		}
	})

	var pguser *models.User
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

	router.Group(func(r chi.Router) {
		r.Use(bsql.Session.Middleware)

		r.Get("/profile", func(w http.ResponseWriter, r *http.Request) {
			session, ok := auth.GetSessionFromContext(r.Context())
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Retrieve user data from the session
			userID, ok := session.Get("user_id").(string)
			if !ok {
				http.Error(w, "User ID not found in session", http.StatusUnauthorized)
				return
			}

			email, _ := session.Get("email").(string)
			w.Write(fmt.Appendf(nil, "User ID: %s, Email: %s", userID, email))
		})

		r.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
			if !bsql.UseSessions {
				w.Write([]byte("Logout not applicable for JWT"))
				return
			}

			cookie, err := r.Cookie("session_id")
			if err != nil {
				http.Error(w, "No session found", http.StatusBadRequest)
				return
			}

			if err := bsql.Session.DeleteSession(cookie.Value); err != nil {
				log.Println("Failed to delete session:", err.Error())
				http.Error(w, "Failed to logout", http.StatusInternalServerError)
				return
			}

			// Clear the session cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "session_id",
				Value:    "",
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   -1, // Deletes the cookie
			})

			w.Write([]byte("Logout successful"))
		})
	})

	func(routes []chi.Route) {
		for _, r := range routes {
			log.Println(r.Pattern)
		}
	}(router.Routes())
	log.Println("Started Server on port 8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}
