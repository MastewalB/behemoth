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

// func (u *User) TableName() string {
// 	return "users"
// }

// func (u *User) PrimaryKey() string {
// 	return "id"
// }

// func (u *User) Fields() []string {
// 	return []string{
// 		"id",
// 		"email",
// 		"username",
// 		"firstname",
// 		"lastname",
// 		"password_hash",
// 		"email_verified",
// 		"image_url",
// 		"created_at",
// 		"updated_at",
// 	}
// }

// func (u *User) PrimaryValue() any {
// 	return u.ID
// }

// func (u *User) ScanDestinations() []any {
// 	return []any{
// 		&u.ID,
// 		&u.Email,
// 		&u.Username,
// 		&u.Firstname,
// 		&u.Lastname,
// 		&u.PasswordHash,
// 		&u.EmailVerified,
// 		&u.ImageUrl,
// 		&u.CreatedAt,
// 		&u.UpdatedAt,
// 	}
// }

func (u *User) SchemaName() string {
	return "users"
}

func (u *User) PrimaryKeyName() string {
	return "id"
}

func (u *User) PrimaryKeyField() any {
	return u.ID
}

func (u *User) New() behemoth.Model {
	return &User{}
}

func (u *User) ToMap() (map[string]any, error) {
	return map[string]any{
		"id":             u.ID,
		"email":          u.Email,
		"username":       u.Username,
		"firstname":      u.Firstname,
		"lastname":       u.Lastname,
		"password_hash":  u.PasswordHash,
		"email_verified": u.EmailVerified,
		"image_url":      u.ImageUrl,
		"created_at":     u.CreatedAt,
		"updated_at":     u.UpdatedAt,
	}, nil
}

func (u *User) FromMap(data map[string]any) error {
	u.ID = data["id"].(string)
	u.Email = data["email"].(string)
	u.Username = data["username"].(string)
	u.Firstname = data["firstname"].(string)
	u.Lastname = data["lastname"].(string)
	u.PasswordHash = data["password_hash"].(string)
	u.EmailVerified = data["email_verified"].(string)
	u.ImageUrl = data["image_url"].(string)
	u.CreatedAt = data["created_at"].(string)
	u.UpdatedAt = data["updated_at"].(string)
	return nil
}

func GenerateColumnValuePairs(m behemoth.Model) (columns []string, values []any, valuePtrs []any) {
	if serializable, ok := m.(behemoth.Serializable); ok {
		data, err := serializable.ToMap()
		if err != nil {
			return nil, nil, nil
		}

		for k := range data {
			columns = append(columns, k)
		}

		// Allocate fixed-size slices
		values = make([]any, len(columns))
		valuePtrs = make([]any, len(columns))

		for i, col := range columns {
			values[i] = data[col]
			valuePtrs[i] = &values[i]
		}
	}
	return columns, values, valuePtrs
}

func GenerateModelFromRows(m behemoth.Model, columns []string, values []any) (behemoth.Model, error) {
	resultMap := map[string]any{}
	for i, col := range columns {
		resultMap[col] = values[i]
	}

	newModel := m.New()
	if serialized, ok := newModel.(behemoth.Serializable); ok {
		if err := serialized.FromMap(resultMap); err != nil {
			return nil, err
		}

		return newModel, nil
	}
	return nil, fmt.Errorf("model does not implement Serializable interface")
}

func UserFactory(data map[string]any) behemoth.User {
	return &User{
		ID:            data["id"].(string),
		Email:         data["email"].(string),
		Username:      data["username"].(string),
		Firstname:     data["firstname"].(string),
		Lastname:      data["lastname"].(string),
		PasswordHash:  data["password_hash"].(string),
		ImageUrl:      data["image_url"].(string),
		EmailVerified: data["email_verified"].(string),
	}
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

func (ui *UserInfo) New() behemoth.Model {
	return &UserInfo{}
}

func (ui *UserInfo) TableName() string {
	return "user_info"
}

func (ui *UserInfo) PrimaryKey() string {
	return "id"
}

func (ui *UserInfo) SchemaName() string {
	return "user_info"
}

func (ui *UserInfo) PrimaryKeyName() string {
	return "id"
}

func (ui *UserInfo) PrimaryKeyField() any {
	return ui.ID
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
