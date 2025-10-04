package models

import (
	"fmt"
	"time"
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
