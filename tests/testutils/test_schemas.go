package testutils

import (
	"fmt"

	"github.com/MastewalB/behemoth"
)

type TestUser struct {
	ID       string
	Email    string
	Username string
}

var TestUserSchema = `
CREATE TABLE users (
	id TEXT PRIMARY KEY,
	email TEXT UNIQUE NOT NULL,
	username TEXT UNIQUE NOT NULL
);
`

func (u *TestUser) TableName() string {
	return "users"
}

func (u *TestUser) PrimaryKey() string {
	return "id"
}

func (u *TestUser) Fields() []string {
	return []string{"id", "email", "username"}
}

func (u *TestUser) PrimaryValue() any {
	return u.ID
}

func (u *TestUser) ScanDestinations() []any {
	return []any{&u.ID, &u.Email, &u.Username}
}

func (u *TestUser) GetID() string {
	return u.ID
}

func (u *TestUser) GetPasswordHash() string {
	return ""
}

func (u *TestUser) New() behemoth.User {
	return &TestUser{}
}

func NewTestUser(id string) *TestUser {
	return &TestUser{
		ID:       id,
		Email:    fmt.Sprintf("user%s@example.com", id),
		Username: fmt.Sprintf("user%s", id),
	}
}
