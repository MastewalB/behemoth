package types

import "github.com/MastewalB/behemoth"

type ErrorMapper interface {
	Map(err error) (status int, body behemoth.M)
}
