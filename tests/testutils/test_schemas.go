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

func (u *TestUser) SchemaName() string {
	return "users"
}

func (u *TestUser) PrimaryKey() string {
	return "id"
}

func (u *TestUser) PrimaryKeyField() any {
	return u.ID
}

func (u *TestUser) PrimaryKeyName() string {
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

func (u *TestUser) New() behemoth.Model {
	return &TestUser{}
}

func (u *TestUser) ToMap() (map[string]any, error) {
	return map[string]any{
		"id":       u.ID,
		"email":    u.Email,
		"username": u.Username,
	}, nil
}

func (u *TestUser) FromMap(data map[string]any) error {
	id, ok := data["id"].(string)
	if !ok {
		return fmt.Errorf("invalid type for id")
	}
	email, ok := data["email"].(string)
	if !ok {
		return fmt.Errorf("invalid type for email")
	}
	username, ok := data["username"].(string)
	if !ok {
		return fmt.Errorf("invalid type for username")
	}

	u.ID = id
	u.Email = email
	u.Username = username
	return nil
}

func NewTestUser(id string) *TestUser {
	return &TestUser{
		ID:       id,
		Email:    fmt.Sprintf("user%s@example.com", id),
		Username: fmt.Sprintf("user%s", id),
	}
}
