package adapters

import (
	"context"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
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

func (adapter *InternalAdapter) FindUserByID(ctx context.Context, model behemoth.Model, id any) (behemoth.User, error) {
	whereClause := clause.Expression{
		Logic: clause.OpAnd,
		Conditions: []clause.Condition{
			{
				Field:    model.PrimaryKeyName(),
				Operator: clause.OpEqual,
				Value:    id,
			},
		},
	}

	found, err := adapter.db.FindOne(ctx, model, whereClause)
	if err != nil {
		return nil, err
	}

	return found.(behemoth.User), nil
}
