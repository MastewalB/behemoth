package models

type User interface {
	GetID() string
	GetPasswordHash() string
	GetEmail() string
}

type DefaultUser struct {
	ID           string
	Email        string
	PasswordHash string
}

func (u *DefaultUser) GetID() string           { return u.ID }
func (u *DefaultUser) GetPasswordHash() string { return u.PasswordHash }
func (u *DefaultUser) GetEmail() string        { return u.Email }
