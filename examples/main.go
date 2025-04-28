package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/auth"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/providers"
	"github.com/MastewalB/behemoth/storage"
	"github.com/MastewalB/behemoth/utils"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
)

var templates *template.Template
var bsql *auth.Behemoth[*models.User]
var bpg *auth.Behemoth[*models.User]
var dbMap map[string]*auth.Behemoth[*models.User]

func main() {

	var err error
	templates, err = template.ParseGlob(filepath.Join("templates", "*.html"))
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}
	err = godotenv.Load()
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
	sqlt, err := sql.Open("sqlite3", "localsqlite.db")
	if err != nil {
		log.Fatalf("Failed to initialize SQLite db: %v", err)
	}

	_, err = sqlt.Exec("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE, username TEXT UNIQUE, firstname TEXT, lastname TEXT, password_hash TEXT)")
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
	}

	pgProvider, err := storage.NewPostgres[*models.User](pg, "users", "email", func(id string) behemoth.Session {
		return behemoth.NewDefaultSession(id, time.Hour)
	})
	if err != nil {
		log.Fatalf("Failed to init Postgres: %v", err)
	}

	pgCfg := &behemoth.Config[*models.User]{
		Password:       &behemoth.PasswordConfig{HashCost: 10},
		OAuthProviders: oauthProviders,
		JWT:            &behemoth.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
		UseDefaultUser: true,
		DB:             pgProvider,
		UserModel:      &models.User{},
		UseSessions:    true,
	}
	bpg = auth.New(pgCfg)

	sqliteProvider, err := storage.NewSQLite[*models.User](sqlt, "users", "email", func(id string) behemoth.Session {
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
	bsql = auth.New(cfg)

	dbMap = map[string]*auth.Behemoth[*models.User]{
		"sqlite": bsql,
		"pg":     bpg,
	}

	router := chi.NewRouter()
	router.Use(middleware.Logger)

	// Simple Home Page
	router.Get("/", handleIndex)

	// Password endpoints
	router.Get("/{db}/register", handleRegisterGet)
	router.Post("/{db}/register", handleRegisterPost)

	router.Get("/{db}/login", handleLoginGet)
	router.Post("/{db}/login", handleLoginPost)

	router.Get("/{db}/users", handleUsersGet)

	dbRouterMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			dbParam := chi.URLParam(r, "db")
			if dbParam == "sqlite" && bsql.Session != nil {
				bsql.Session.Middleware(next).ServeHTTP(w, r) // Call the SQLite session middleware
			} else if dbParam == "pg" && bpg.Session != nil {
				bpg.Session.Middleware(next).ServeHTTP(w, r) // Call the Postgres session middleware
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
	router.Group(func(r chi.Router) {
		r.Use(dbRouterMiddleware)

		r.Get("/{db}/profile", handleProfile)

		r.Get("/{db}/update", handleUpdateGet)

		r.Post("/{db}/update", handleUpdatePost)

		r.Post("/{db}/delete", handleDelete)

		r.Get("/{db}/logout", handleLogout)
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

func renderTemplate(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := templates.ExecuteTemplate(w, name, data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
	}
}

func renderMessage(w http.ResponseWriter, title, message, details any, redirectLink *string) {
	data := map[string]any{
		"Title":   title,
		"Message": message,
		"Details": details,
	}
	if redirectLink != nil {
		data["RedirectLink"] = *redirectLink
	}
	renderTemplate(w, "message.html", data)
}

func handleUsersGet(w http.ResponseWriter, r *http.Request) {
	dbParam := chi.URLParam(r, "db")
	db, exists := dbMap[dbParam]
	if !exists {
		renderTemplate(w, "users.html", map[string]any{"Error": "Invalid database selection"})
		return
	}

	users, err := db.DB.GetAllUsers()
	if err != nil {
		log.Printf("Error fetching users: %v", err)
		renderTemplate(w, "users.html", map[string]any{"Error": "Failed to fetch users"})
		return
	}

	data := map[string]any{
		"Users": users,
	}

	renderTemplate(w, "users.html", data)
}

func handleLoginGet(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "login.html", map[string]any{
		"DB": chi.URLParam(r, "db"),
	})
}

func handleRegisterGet(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "register.html", map[string]any{
		"DB": chi.URLParam(r, "db"),
	})
}

func handleUpdateGet(w http.ResponseWriter, r *http.Request) {
	session, ok := auth.GetSessionFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	userID, ok := session.Get("user_id").(string)
	if !ok || userID == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Get the database selection from the URL (either "sqlite" or "pg")
	dbParam := chi.URLParam(r, "db")
	db, exists := dbMap[dbParam]
	if !exists {
		http.Error(w, "Invalid database selection", http.StatusBadRequest)
		return
	}

	user, err := db.DB.FindByPK(userID)
	if err != nil {
		log.Printf("Error fetching user data: %v", err)
		renderTemplate(w, "update.html", map[string]any{"Error": "Failed to fetch user data"})
		return
	}

	formData := map[string]string{
		"id":        user.GetID(),
		"email":     user.Email,
		"username":  user.Username,
		"firstname": user.Firstname,
		"lastname":  user.Lastname,
	}

	renderTemplate(w, "update.html", map[string]any{
		"FormData": formData,
	})
}

func handleRegisterPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Printf("Error parsing registration form: %v", err)
		// Render form again with a generic error
		renderTemplate(w, "register.html", map[string]any{
			"Error": "Failed to parse form data",
			"DB":    chi.URLParam(r, "db"),
		})
		return
	}

	dbParam := chi.URLParam(r, "db")
	db := dbMap[dbParam]

	email := r.FormValue("email")
	username := r.FormValue("username")
	firstname := r.FormValue("firstname")
	lastname := r.FormValue("lastname")
	password := r.FormValue("password")

	formData := map[string]string{
		"email":     email,
		"username":  username,
		"firstname": firstname,
		"lastname":  lastname,
	}

	// Basic validation
	if email == "" || username == "" || password == "" {
		// Re-render form with error and retain entered values
		renderTemplate(w, "register.html", map[string]any{
			"Error":    "Email, Username, and Password are required.",
			"FormData": formData,
			"DB":       chi.URLParam(r, "db"),
		})
		return
	}

	log.Printf(
		"Registering user: %v, %v, %v, %v, %v",
		email, username, firstname, lastname, dbParam,
	)

	_, err := db.Password.Create(email, username, firstname, lastname, password)
	if err != nil {
		log.Printf("Registration failed for email %s: %v", email, err)
		// Re-render form with specific error and retain entered values
		renderTemplate(w, "register.html", map[string]any{
			"Error":    fmt.Sprintf("Registration failed: %v", err),
			"FormData": r.Form,
			"DB":       chi.URLParam(r, "db"),
		})
		return
	}

	// Success - render success message or redirect to login
	log.Printf("User registered successfully: %s / %s", email, username)
	loginLink := "/login"
	renderMessage(w, "Registration Successful", "Your account has been created.", nil, &loginLink)
}

func handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Printf("Error parsing login form: %v", err)
		renderTemplate(w, "login.html", map[string]any{"Error": "Failed to parse form data"})
		return
	}

	dbParam := chi.URLParam(r, "db")
	db := dbMap[dbParam]
	email := r.FormValue("email")
	password := r.FormValue("password")

	formData := map[string]string{
		"email": email,
	}

	if email == "" || password == "" {
		renderTemplate(w, "login.html", map[string]any{
			"Error":    "Id and Password are required.",
			"FormData": formData, // Keep email field populated
		})
		return
	}

	// Attempt password authentication
	user, err := db.Password.Authenticate(auth.PasswordCredentials{
		PK:       email,
		Password: password,
	})

	if err != nil {
		log.Printf("Password authentication failed for user ID %s: %v", email, err)
		renderTemplate(w, "login.html", map[string]any{
			"Error":    "Login failed (invalid credentials).",
			"FormData": formData,
		})
		return
	}

	// --- Session/JWT Handling ---
	if db.UseSessions && db.Session != nil {
		session, err := db.Session.CreateSession()

		if err != nil {
			log.Println("Failed to create session:", err.Error())
			renderTemplate(w, "login.html", map[string]any{
				"Error":    "Login failed (could not create session).",
				"FormData": formData,
			})
			return
		}

		session.Set("user_id", user.GetID()) // Error handling omitted for brevity
		// Set email if possible
		if defaultUser, ok := user.(*models.User); ok {
			session.Set("email", defaultUser.Email)
		}

		if _, err := db.Session.UpdateSession(session); err != nil {
			log.Println("Failed to save session:", err.Error())
			renderTemplate(w, "login.html", map[string]any{
				"Error":    "Login failed (could not save session).",
				"FormData": formData,
			})
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    session.SessionID(),
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(db.Session.Expiry().Seconds()),
		})

		log.Printf("User logged in successfully (session): %s", user.GetID())
		http.Redirect(w, r, fmt.Sprintf("/%s/profile", dbParam), http.StatusSeeOther) // Redirect to profile on success
		return

	} else if db.JWT != nil { // Fallback to JWT
		token, err := db.JWT.GenerateToken(user)
		if err != nil {
			log.Println("Failed to generate token:", err.Error())
			renderTemplate(w, "login.html", map[string]any{
				"Error":    "Login succeeded, but failed to generate token.",
				"FormData": formData,
			})
			return
		}
		log.Printf("User logged in successfully (JWT): %s", user.GetID())
		// Render message page showing token
		renderMessage(w, "Login Successful (JWT)", "Your JWT Token:", token, nil)

	} else {
		log.Println("Error: Login succeeded but no session manager or JWT service configured.")
		renderTemplate(w, "login.html", map[string]any{
			"Error":    "Login failed (server configuration error).",
			"FormData": formData,
		})
	}
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	dbParam := chi.URLParam(r, "db")
	db, exists := dbMap[dbParam]
	if !exists {
		http.Error(w, "Invalid database selection", http.StatusBadRequest)
		return
	}

	session, ok := auth.GetSessionFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, fmt.Sprintf("/{%s}/login", dbParam), http.StatusSeeOther) // Redirect to login if no session
		return
	}

	// userID, _ := session.Get("user_id").(string)
	

	email, _ := session.Get("email").(string)

	user, err := db.DB.FindByPK(email)
	if err != nil {
		log.Printf("Error fetching user data: %v", err)
		renderTemplate(w, "update.html", map[string]any{"Error": "Failed to fetch user data"})
		return
	}

	formData := map[string]string{
		"id":        user.GetID(),
		"email":     user.Email,
		"username":  user.Username,
		"firstname": user.Firstname,
		"lastname":  user.Lastname,
	}

	renderTemplate(w, "update.html", map[string]any{
		"Title":    "Your Profile",
		"FormData": formData,
		"DB":       dbParam,
	})
}

func handleUpdatePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Printf("Error parsing update form: %v", err)
		// Render form again with a generic error
		renderTemplate(w, "update.html", map[string]any{"Error": "Failed to parse form data"})
		return
	}

	dbParam := chi.URLParam(r, "db")
	db := dbMap[dbParam]
	email := r.FormValue("email")
	username := r.FormValue("username")
	firstname := r.FormValue("firstname")
	lastname := r.FormValue("lastname")

	user, err := db.DB.FindByPK(email)
	if err != nil {
		log.Printf("Error fetching user data: %v", err)
		renderTemplate(w, "update.html", map[string]any{"Error": "Failed to fetch user data"})
		return
	}

	user = &models.User{
		ID:           user.GetID(),
		Email:        email,
		Username:     username,
		Firstname:    firstname,
		Lastname:     lastname,
		PasswordHash: user.PasswordHash,
	}

	_, err = db.DB.UpdateUser(user)
	if err != nil {
		log.Printf("Update failed for email %s: %v", email, err)
		// Re-render form with specific error and retain entered values
		renderTemplate(w, "update.html", map[string]any{
			"Error":    fmt.Sprintf("Update failed: %v", err),
			"FormData": r.Form,
		})
		return
	}

	formData := map[string]string{
		"id":        user.GetID(),
		"email":     user.Email,
		"username":  user.Username,
		"firstname": user.Firstname,
		"lastname":  user.Lastname,
	}

	// Success - render success message or redirect to login
	log.Printf("User updated successfully: %s / %s", email, username)
	renderTemplate(w, "update.html", map[string]any{
		"Message":  "User updated successfully",
		"FormData": formData,
		"DB":       dbParam,
	})
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Printf("Error parsing update form: %v", err)
		// Render form again with a generic error
		renderTemplate(w, "update.html", map[string]any{"Error": "Failed to parse form data"})
		return
	}

	dbParam := chi.URLParam(r, "db")
	db := dbMap[dbParam]
	email := r.FormValue("email")

	session, ok := auth.GetSessionFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, fmt.Sprintf("/{%s}/login", dbParam), http.StatusSeeOther) // Redirect to login if no session
		return
	}

	user, err := db.DB.FindByPK(email)
	if err != nil {
		log.Printf("Error fetching user data: %v", err)
		renderTemplate(w, "update.html", map[string]any{"Error": "Failed to fetch user data"})
		return
	}

	// Delete the session from storage
	if err := db.Session.DeleteSession(session.SessionID()); err != nil {
		log.Printf("Failed to delete session %s from storage: %v", session.SessionID(), err)
		renderMessage(w, "Error", "Couldn't logout.", "", nil)
		return
	}

	// Clear the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // Deletes the cookie
	})
	
	err = db.DB.DeleteUser(user)
	if err != nil {
		log.Printf("Delete failed for email %s: %v", email, err)
		// Re-render form with specific error and retain entered values
		renderTemplate(w, "update.html", map[string]any{
			"Error":    fmt.Sprintf("Delete failed: %v", err),
			"FormData": r.Form,
		})
		return
	}

	log.Printf("User deleted successfully: %s", email)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {

	dbParam := chi.URLParam(r, "db")
	db := dbMap[dbParam]

	if !db.UseSessions || db.Session == nil {
		renderMessage(w, "Logout", "Logout is only applicable when sessions are enabled.", "", nil)
		return
	}

	session, ok := auth.GetSessionFromContext(r.Context())
	if !ok {
		// No active session according to middleware, maybe already logged out or cookie expired
		renderMessage(w, "Logout", "You are not logged in or your session has expired.", "", nil)
		return
	}

	// Delete the session from storage
	if err := db.Session.DeleteSession(session.SessionID()); err != nil {
		log.Printf("Failed to delete session %s from storage: %v", session.SessionID(), err)
		renderMessage(w, "Error", "Couldn't logout.", "", nil)
		return
	}

	// Clear the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // Deletes the cookie
	})

	log.Printf("User logged out, session deleted: %s", session.SessionID())
	homeLink := "/"
	renderMessage(w, "Logout Successful", "You have been logged out.", nil, &homeLink)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	userID := ""
	// Check session status (using bsql - the SQLite instance with sessions)
	if bsql != nil && bsql.UseSessions && bsql.Session != nil {
		// Attempt to get session. This might fail if middleware isn't applied
		// to '/' or if no valid session cookie exists.
		session, ok := auth.GetSessionFromContext(r.Context())
		if ok {
			id, exists := session.Get("user_id").(string)
			if exists {
				userID = id
			}
		}
	}

	// Get OAuth provider names (using bsql instance)
	// var providerNames []string
	// if bsql != nil && bsql.OAuth != nil {
	// 	providersList := bsql.OAuth.GetProviders()
	// 	providerNames = make([]string, len(providersList))
	// 	for i, p := range providersList {
	// 		providerNames[i] = p.Name()
	// 	}
	// }

	// Check if Postgres instance (bpg) is configured and was successfully initialized
	postgresEnabled := bpg != nil

	// Prepare data for the template
	data := map[string]any{
		"UserID":          userID,
		"OAuthProviders":  nil,
		"PostgresEnabled": postgresEnabled,
	}

	// Render the index template
	renderTemplate(w, "index.html", data)
}
