package testutils

import (
	"fmt"
	"strconv"
	"time"

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
	email TEXT NOT NULL,
	username TEXT UNIQUE NOT NULL
);
`

var TestMySQLUserSchema = `
CREATE TABLE users (
    id CHAR(36) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL UNIQUE
);
`

func (u *TestUser) SchemaName() string {
	return "users"
}

func (u *TestUser) PrimaryKeyField() any {
	return u.ID
}

func (u *TestUser) PrimaryKeyName() string {
	return "id"
}

func (u *TestUser) GetID() string {
	return u.ID
}

func (u *TestUser) GetEmail() string {
	return u.Email
}

func (u *TestUser) GetUsername() string {
	return u.Username
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
	toString := func(v any) string {
		switch x := v.(type) {
		case string:
			return x
		case []byte:
			return string(x)
		default:
			return ""
		}
	}

	u.ID = toString(data["id"])
	u.Email = toString(data["email"])
	u.Username = toString(data["username"])

	return nil
}

func NewTestUser(id string) *TestUser {
	t := strconv.FormatInt(time.Now().UnixNano(), 10)

	return &TestUser{
		ID:       id,
		Email:    fmt.Sprintf("user%s@example.com", id),
		Username: t,
	}
}

func NewTestUserMap(id int) behemoth.M {
	return behemoth.M{
		"id":       strconv.Itoa(id),
		"email":    fmt.Sprintf("user%d@example.com", id),
		"username": fmt.Sprintf("user%d", id),
	}
}

type GormTestUser struct {
	ID       string `gorm:"primaryKey"`
	Email    string `gorm:"not null"`
	Username string `gorm:"unique;not null"`
}

func (u *GormTestUser) SchemaName() string {
	return "users"
}

func (u *GormTestUser) TableName() string {
	return "users"
}

func (u *GormTestUser) PrimaryKeyField() any {
	return u.ID
}

func (u *GormTestUser) PrimaryKeyName() string {
	return "id"
}

func (u *GormTestUser) GetID() string {
	return u.ID
}

func (u *GormTestUser) GetEmail() string {
	return u.Email
}

func (u *GormTestUser) GetUsername() string {
	return u.Username
}

func (u *GormTestUser) GetPasswordHash() string {
	return ""
}

func (u *GormTestUser) New() behemoth.Model {
	return &GormTestUser{}
}

func (u *GormTestUser) ToMap() (map[string]any, error) {
	return map[string]any{
		"id":       u.ID,
		"email":    u.Email,
		"username": u.Username,
	}, nil
}

func (u *GormTestUser) FromMap(data map[string]any) error {
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

func NewGormTestUser(id string) *GormTestUser {
	return &GormTestUser{
		ID:       id,
		Email:    fmt.Sprintf("user%s@example.com", id),
		Username: fmt.Sprintf("user%s", id),
	}
}
