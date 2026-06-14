package auth

// import (
// 	"database/sql"
// 	"testing"

// 	"github.com/MastewalB/behemoth"
// 	"github.com/MastewalB/behemoth/auth"
// 	"github.com/MastewalB/behemoth/models"
// 	"github.com/MastewalB/behemoth/tests/testutils"
// 	"github.com/stretchr/testify/assert"
// )

// var defaultUserSchema = `
// CREATE TABLE users (
// 	id TEXT PRIMARY KEY,
// 	email TEXT UNIQUE NOT NULL,
// 	username TEXT UNIQUE NOT NULL,
// 	firstname TEXT,
// 	lastname TEXT,
// 	password_hash TEXT NOT NULL,
// 	email_verified TEXT,
// 	image_url TEXT,
// 	created_at TEXT,
// 	updated_at TEXT
// );
// `

// func getBehemothInstanceDefaultUser(
// 	db *sql.DB,
// 	UsePassword bool,
// 	UseEmailAndPassword bool,
// ) (*auth.Behemoth[*models.User], error) {
// 	config := &behemoth.Config[*models.User]{
// 		DatabaseConfig: behemoth.DatabaseConfig{
// 			Name:           behemoth.SQLite,
// 			DB:             db,
// 			UseDefaultUser: false,
// 			UserModel:      &models.User{},
// 			UserFactory:    models.UserFactory,
// 		},
// 		Password:                &behemoth.PasswordConfig{HashCost: 10},
// 		UseEmailAndPasswordAuth: UseEmailAndPassword,
// 		// OAuthProviders: []behemoth.Provider{},
// 		JWT:         &behemoth.JWTConfig{Secret: "default_secret", Expiry: 24 * 60 * 60},
// 		UseSessions: false,
// 	}

// 	return auth.New(config)
// }

// func TestDefaultUserPasswordAuth_Register(t *testing.T) {
// 	db := testutils.SetupTestDB(t, &defaultUserSchema)
// 	defer db.Close()

// 	bmth, err := getBehemothInstanceDefaultUser(db, true, false)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, bmth)

// 	registrationData := map[string]any{
// 		"email":     "custom_user@email.com",
// 		"username":  "customuser",
// 		"firstname": "Custom",
// 		"lastname":  "User",
// 		"password":  "securepassword",
// 		"image_url": "http://example.com/avatar.png",
// 	}

// 	found, err := bmth.Password.Register(registrationData)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, found)
// 	registeredUser, ok := found.(*models.User)
// 	assert.True(t, ok)

// 	assert.Equal(t, registrationData["email"], registeredUser.Email)
// 	assert.Equal(t, registrationData["username"], registeredUser.Username)
// 	assert.Equal(t, registrationData["firstname"], registeredUser.Firstname)
// 	assert.Equal(t, registrationData["lastname"], registeredUser.Lastname)
// 	assert.Equal(t, registrationData["image_url"], registeredUser.ImageUrl)
// 	assert.Equal(t, "false", registeredUser.EmailVerified)
// 	assert.NotEmpty(t, registeredUser.PasswordHash)

// }

// func TestDefaultUserPasswordAuth_Login(t *testing.T) {
// 	db := testutils.SetupTestDB(t, &defaultUserSchema)
// 	defer db.Close()

// 	bmth, err := getBehemothInstanceDefaultUser(db, true, false)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, bmth)

// 	// First, register a user
// 	registrationData := map[string]any{
// 		"email":     "custom_user@email.com",
// 		"username":  "customuser",
// 		"firstname": "Custom",
// 		"lastname":  "User",
// 		"password":  "securepassword",
// 		"image_url": "http://example.com/avatar.png",
// 	}

// 	created, err := bmth.Password.Register(registrationData)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, created)

// 	registeredUser, ok := created.(*models.User)
// 	assert.True(t, ok)

// 	credentials := auth.PasswordCredentials{
// 		PrimaryKey: registeredUser.ID,
// 		Password:   "securepassword",
// 	}

// 	authenticatedUser, err := bmth.Password.Login(credentials)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, authenticatedUser)
// 	assert.Equal(t, registeredUser.ID, authenticatedUser.GetID())
// 	assert.Equal(t, registeredUser.Email, authenticatedUser.(*models.User).Email)

// }

// func TestDefaultUserPasswordAuth_Login_IncorrectCredential(t *testing.T) {
// 	db := testutils.SetupTestDB(t, &defaultUserSchema)
// 	defer db.Close()

// 	bmth, err := getBehemothInstanceDefaultUser(db, true, false)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, bmth)

// 	registrationData := map[string]any{
// 		"email":     "custom_user@email.com",
// 		"username":  "customuser",
// 		"firstname": "Custom",
// 		"lastname":  "User",
// 		"password":  "securepassword",
// 		"image_url": "http://example.com/avatar.png",
// 	}

// 	created, err := bmth.Password.Register(registrationData)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, created)

// 	registeredUser, ok := created.(*models.User)
// 	assert.True(t, ok)

// 	credentials := auth.PasswordCredentials{
// 		PrimaryKey: registeredUser.ID,
// 		Password:   "wrongpassword",
// 	}
// 	authenticatedUser, err := bmth.Password.Login(credentials)
// 	assert.Error(t, err)
// 	assert.Nil(t, authenticatedUser)
// }

// /* Email and Password Auth tests*/
// // email and password - valid registration and login
// // email and password - invalid login credentials
// // email and password - invalid email format during registration
// // email and password - invalid email format during login

// func TestDefaultUserEmailAndPasswordAuth_Register(t *testing.T) {
// 	db := testutils.SetupTestDB(t, &defaultUserSchema)
// 	defer db.Close()

// 	bmth, err := getBehemothInstanceDefaultUser(db, false, true)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, bmth)

// 	registrationData := map[string]any{
// 		"email":     "defaultuser@default.com",
// 		"username":  "defaultuser",
// 		"firstname": "Default",
// 		"lastname":  "User",
// 		"password":  "securepassword",
// 		"image_url": "http://example.com/avatar.png",
// 	}

// 	found, err := bmth.EmailAndPassword.Register(registrationData)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, found)
// 	registeredUser, ok := found.(*models.User)
// 	assert.True(t, ok)

// 	assert.Equal(t, registrationData["email"], registeredUser.Email)
// 	assert.Equal(t, registrationData["username"], registeredUser.Username)
// 	assert.Equal(t, registrationData["firstname"], registeredUser.Firstname)
// 	assert.Equal(t, registrationData["lastname"], registeredUser.Lastname)
// 	assert.Equal(t, registrationData["image_url"], registeredUser.ImageUrl)
// 	assert.Equal(t, "false", registeredUser.EmailVerified)
// 	assert.NotEmpty(t, registeredUser.PasswordHash)
// }

// func TestDefaultUserEmailAndPasswordAuth_Login(t *testing.T) {
// 	db := testutils.SetupTestDB(t, &defaultUserSchema)
// 	defer db.Close()

// 	bmth, err := getBehemothInstanceDefaultUser(db, false, true)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, bmth)

// 	registrationData := map[string]any{
// 		"email":     "defaultuser@default.com",
// 		"username":  "defaultuser",
// 		"firstname": "Default",
// 		"lastname":  "User",
// 		"password":  "securepassword",
// 		"image_url": "http://example.com/avatar.png",
// 	}

// 	found, err := bmth.EmailAndPassword.Register(registrationData)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, found)
// 	registeredUser, ok := found.(*models.User)
// 	assert.True(t, ok)

// 	credentials := auth.EmailAndPasswordCredentials{
// 		Email:    registeredUser.Email,
// 		Password: "securepassword",
// 	}

// 	authenticatedUser, err := bmth.EmailAndPassword.Login(credentials)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, authenticatedUser)
// 	assert.Equal(t, registeredUser.ID, authenticatedUser.GetID())
// 	assert.Equal(t, registeredUser.Email, authenticatedUser.(*models.User).Email)

// }

// func TestDefaultUserEmailAndPasswordAuth_Login_IncorrectCredential(t *testing.T) {
// 	db := testutils.SetupTestDB(t, &defaultUserSchema)
// 	defer db.Close()

// 	bmth, err := getBehemothInstanceDefaultUser(db, false, true)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, bmth)

// 	registrationData := map[string]any{
// 		"email":     "defaultuser@default.com",
// 		"username":  "defaultuser",
// 		"firstname": "Default",
// 		"lastname":  "User",
// 		"password":  "securepassword",
// 		"image_url": "http://example.com/avatar.png",
// 	}

// 	found, err := bmth.EmailAndPassword.Register(registrationData)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, found)
// 	registeredUser, ok := found.(*models.User)
// 	assert.True(t, ok)

// 	credentials := auth.EmailAndPasswordCredentials{
// 		Email:    registeredUser.Email,
// 		Password: "wrongpassword",
// 	}
// 	authenticatedUser, err := bmth.EmailAndPassword.Login(credentials)
// 	assert.Error(t, err)
// 	assert.Nil(t, authenticatedUser)
// }

// func TestDefaultUserEmailAndPasswordAuth_Register_InvalidEmail(t *testing.T) {
// 	db := testutils.SetupTestDB(t, &defaultUserSchema)
// 	defer db.Close()

// 	bmth, err := getBehemothInstanceDefaultUser(db, false, true)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, bmth)

// 	registrationData := map[string]any{
// 		"email":     "invaliddefault.com",
// 		"username":  "defaultuser",
// 		"firstname": "Default",
// 		"lastname":  "User",
// 		"password":  "securepassword",
// 		"image_url": "http://example.com/avatar.png",
// 	}

// 	registered, err := bmth.EmailAndPassword.Register(registrationData)
// 	assert.Error(t, err)
// 	assert.Nil(t, registered)

// }

// func TestDefaultUserEmailAndPasswordAuth_Login_InvalidEmail(t *testing.T) {
// 	db := testutils.SetupTestDB(t, &defaultUserSchema)
// 	defer db.Close()

// 	bmth, err := getBehemothInstanceDefaultUser(db, false, true)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, bmth)

// 	registrationData := map[string]any{
// 		"email":     "defaultuser@default.com",
// 		"username":  "defaultuser",
// 		"firstname": "Default",
// 		"lastname":  "User",
// 		"password":  "securepassword",
// 		"image_url": "http://example.com/avatar.png",
// 	}

// 	found, err := bmth.EmailAndPassword.Register(registrationData)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, found)
// 	registeredUser, ok := found.(*models.User)
// 	assert.True(t, ok)
// 	assert.NotNil(t, registeredUser)

// 	credentials := auth.EmailAndPasswordCredentials{
// 		Email:    "invaliddefault.com",
// 		Password: "securepassword",
// 	}

// 	authenticatedUser, err := bmth.EmailAndPassword.Login(credentials)
// 	assert.Error(t, err)
// 	assert.Nil(t, authenticatedUser)
// }
