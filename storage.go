package behemoth

type Database[T User] interface {
	FindByPK(val any) (T, error)
	SaveUser(user *DefaultUser) error
}
