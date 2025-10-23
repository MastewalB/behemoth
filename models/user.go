package models

import (
	"fmt"
	"time"

	"github.com/MastewalB/behemoth"
)

type User struct {
	ID            string `db:"id"`
	Email         string `db:"email"`
	Username      string `db:"username"`
	Firstname     string `db:"firstname"`
	Lastname      string `db:"lastname"`
	PasswordHash  string `db:"password_hash"`
	EmailVerified string `db:"email_verified"`
	ImageUrl      string `db:"image_url"`
	CreatedAt     string `db:"created_at"`
	UpdatedAt     string `db:"updated_at"`
}

func (u *User) GetID() string           { return u.ID }
func (u *User) GetPasswordHash() string { return u.PasswordHash }
func (u *User) GetEmail() string        { return u.Email }
func (u *User) GetUsername() string     { return u.Username }
func (u *User) GetFirstname() string    { return u.Firstname }
func (u *User) GetLastname() string     { return u.Lastname }
func (u *User) GetName() string         { return fmt.Sprintf("%s %s", u.Firstname, u.Lastname) }

// Functions required to satisfy the Model interface

func (u *User) TableName() string {
	return "users"
}

func (u *User) PrimaryKey() string {
	return "id"
}

func (u *User) Fields() []string {
	return []string{
		"id",
		"email",
		"username",
		"firstname",
		"lastname",
		"password_hash",
		"email_verified",
		"image_url",
		"created_at",
		"updated_at",
	}
}

func (u *User) PrimaryValue() any {
	return u.ID
}

func (u *User) ScanDestinations() []any {
	return []any{
		&u.ID,
		&u.Email,
		&u.Username,
		&u.Firstname,
		&u.Lastname,
		&u.PasswordHash,
		&u.EmailVerified,
		&u.ImageUrl,
		&u.CreatedAt,
		&u.UpdatedAt,
	}
}

func (u *User) New() behemoth.User {
	return &User{}
}

func (u *User) FromUserInfo(userInfo UserInfo) {
	u.Email = userInfo.Email
	u.Username = userInfo.Email
	u.Firstname = userInfo.FirstName
	u.Lastname = userInfo.LastName
}

type UserInfo struct {
	Provider          string
	Email             string
	Name              string
	FirstName         string
	LastName          string
	ID                string
	AvatarURL         string
	Location          string
	AccessToken       string
	AccessTokenSecret string
	RefreshToken      string
	ExpiresAt         time.Time
	IDToken           string
}

func (ui *UserInfo) GetID() string {
	return ui.ID
}

func (ui *UserInfo) GetPasswordHash() string {
	return ""
}

func (ui *UserInfo) New() behemoth.User {
	return &UserInfo{}
}

func (ui *UserInfo) TableName() string {
	return "user_info"
}

func (ui *UserInfo) PrimaryKey() string {
	return "id"
}

func (ui *UserInfo) Fields() []string {
	return []string{
		"provider",
		"email",
		"name",
		"first_name",
		"last_name",
		"id",
		"avatar_url",
		"location",
		"access_token",
		"access_token_secret",
		"refresh_token",
		"expires_at",
		"id_token",
	}
}

func (ui *UserInfo) PrimaryValue() any {
	return ui.ID
}

func (ui *UserInfo) ScanDestinations() []any {
	return []any{
		&ui.Provider,
		&ui.Email,
		&ui.Name,
		&ui.FirstName,
		&ui.LastName,
		&ui.ID,
		&ui.AvatarURL,
		&ui.Location,
		&ui.AccessToken,
		&ui.AccessTokenSecret,
		&ui.RefreshToken,
		&ui.ExpiresAt,
		&ui.IDToken,
	}
}
