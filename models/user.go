package models

import "fmt"

type User interface {
	GetID() string
	GetPasswordHash() string
	GetEmail() string
}

type DefaultUser struct {
	ID           string
	Email        string
	Username     string
	Firstname    string
	Lastname     string
	PasswordHash string
}

func (u *DefaultUser) GetID() string           { return u.ID }
func (u *DefaultUser) GetPasswordHash() string { return u.PasswordHash }
func (u *DefaultUser) GetEmail() string        { return u.Email }
func (u *DefaultUser) GetUsername() string     { return u.Username }
func (u *DefaultUser) GetFirstname() string    { return u.Firstname }
func (u *DefaultUser) GetLastname() string     { return u.Lastname }
func (u *DefaultUser) GetName() string         { return fmt.Sprintf("%s %s", u.Firstname, u.Lastname) }
