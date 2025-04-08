package main

type CustomUser struct {
	ID           string
	Email        string
	PasswordHash string
	Role         string
	Username     string
	Firstname    string
	Lastname     string
}

func (u *CustomUser) GetID() string           { return u.ID }
func (u *CustomUser) GetPasswordHash() string { return u.PasswordHash }
func (u *CustomUser) GetEmail() string        { return u.Email }
func (u *CustomUser) GetUsername() string     { return u.Username }
