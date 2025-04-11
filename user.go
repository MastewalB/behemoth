package behemoth

type User interface {
	GetID() string
	GetPasswordHash() string
}
