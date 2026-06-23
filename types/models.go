package types

type User interface {
	Model
	GetID() string
	GetPasswordHash() string
	// New() User
}
