package models

import (
	"fmt"
	"time"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
)

type User struct {
	ID            string    `db:"id"`
	Email         string    `db:"email"`
	Username      string    `db:"username"`
	Firstname     string    `db:"firstname"`
	Lastname      string    `db:"lastname"`
	PasswordHash  string    `db:"password_hash"`
	EmailVerified string    `db:"email_verified"`
	ImageUrl      string    `db:"image_url"`
	CreatedAt     time.Time `db:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"`
}

func (u *User) GetID() string           { return u.ID }
func (u *User) GetPasswordHash() string { return u.PasswordHash }
func (u *User) GetEmail() string        { return u.Email }
func (u *User) GetUsername() string     { return u.Username }
func (u *User) GetFirstname() string    { return u.Firstname }
func (u *User) GetLastname() string     { return u.Lastname }
func (u *User) GetName() string         { return fmt.Sprintf("%s %s", u.Firstname, u.Lastname) }

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
	id, ok := data["id"].(string)
	if !ok {
		id = ""
	}
	email, ok := data["email"].(string)
	if !ok {
		email = ""
	}
	username, ok := data["username"].(string)
	if !ok {
		username = ""
	}
	firstname, ok := data["firstname"].(string)
	if !ok {
		firstname = ""
	}
	lastname, ok := data["lastname"].(string)
	if !ok {
		lastname = ""
	}
	passwordHash, ok := data["password_hash"].(string)
	if !ok {
		passwordHash = ""
	}
	emailVerified, ok := data["email_verified"].(string)
	if !ok {
		emailVerified = ""
	}
	imageUrl, ok := data["image_url"].(string)
	if !ok {
		imageUrl = ""
	}
	createdAt, ok := data["created_at"].(time.Time)
	if !ok {
		createdAt = time.Time{}
	}
	updatedAt, ok := data["updated_at"].(time.Time)
	if !ok {
		updatedAt = time.Time{}
	}

	u.ID = id
	u.Email = email
	u.Username = username
	u.Firstname = firstname
	u.Lastname = lastname
	u.PasswordHash = passwordHash
	u.EmailVerified = emailVerified
	u.ImageUrl = imageUrl
	u.CreatedAt = createdAt
	u.UpdatedAt = updatedAt
	return nil
}

// GenerateColumnValuePairs constructs three parallel slices from a behemoth.Model:
//   - columns:   names of columns extracted from m.ToMap()
//   - values:    concrete values corresponding to each column
//   - valuePtrs: pointers to each element in values (useful for database scans)
//
// Behavior:
//   - If m implements behemoth.Serializable, ToMap() is called to obtain a map[string]any.
//   - Columns are collected from the map's keys (map iteration order is not deterministic).
//   - values and valuePtrs are allocated to match the number of columns.
//   - If m does not implement behemoth.Serializable or ToMap() returns an error,
//     the function returns nil, nil, nil.
//
// Note:
//   - The columns slice order is determined by the iteration order of the map returned by ToMap().
//

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

// GenerateModelFromRows constructs a new behemoth.Model instance populated from
// parallel slices of column names and values.
//
// Parameters:
//   - m: a prototype model used to create a new instance via m.New().
//   - columns: slice of column names.
//   - values: slice of values; values[i] corresponds to columns[i].
//
// Behavior:
//   - Builds a map[string]any from columns and values (assumes len(values) >= len(columns)).
//   - Calls m.New() to obtain a fresh model instance.
//   - If the new instance implements behemoth.Serializable, calls FromMap(resultMap)
//     to populate the model and returns it.
//   - Returns an error if the new model does not implement behemoth.Serializable
//     or if FromMap returns an error.
//
// Notes:
//   - The order and alignment of columns and values must match the source rows.
//   - Database driver types (e.g., []uint8 for blobs) are passed through as-is.
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
	return nil, behemotherr.SerializableNotImplemented()
}

func GenerateColumnValuePairsWithSelectFilter(m behemoth.Model, selected []string) (columns []string, values []any, valuePtrs []any) {
	if len(selected) == 0 {
		return GenerateColumnValuePairs(m)
	}

	if serializable, ok := m.(behemoth.Serializable); ok {
		data, err := serializable.ToMap()
		if err != nil {
			return nil, nil, nil
		}

		selectedSet := make(map[string]struct{})
		for _, col := range selected {
			selectedSet[col] = struct{}{}
		}
		for k := range data {
			if _, ok := selectedSet[k]; !ok {
				continue
			}
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

// func (ui *UserInfo) Fields() []string {
// 	return []string{
// 		"provider",
// 		"email",
// 		"name",
// 		"first_name",
// 		"last_name",
// 		"id",
// 		"avatar_url",
// 		"location",
// 		"access_token",
// 		"access_token_secret",
// 		"refresh_token",
// 		"expires_at",
// 		"id_token",
// 	}
// }

// func (ui *UserInfo) PrimaryValue() any {
// 	return ui.ID
// }

// func (ui *UserInfo) ScanDestinations() []any {
// 	return []any{
// 		&ui.Provider,
// 		&ui.Email,
// 		&ui.Name,
// 		&ui.FirstName,
// 		&ui.LastName,
// 		&ui.ID,
// 		&ui.AvatarURL,
// 		&ui.Location,
// 		&ui.AccessToken,
// 		&ui.AccessTokenSecret,
// 		&ui.RefreshToken,
// 		&ui.ExpiresAt,
// 		&ui.IDToken,
// 	}
// }
