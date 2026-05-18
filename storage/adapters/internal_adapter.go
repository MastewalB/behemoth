package adapters

import (
	"context"

	"github.com/MastewalB/behemoth"
)

type InternalAdapter struct {
	db behemoth.Database
}

func (adapter *InternalAdapter) CreateUser(ctx context.Context, model behemoth.Model, user behemoth.M) (behemoth.User, error) {

	err := adapter.db.Create(ctx, model)
	if err != nil {
		return nil, err
	}

	return model.(behemoth.User), nil
}
