package adapters

import (
	"context"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	"github.com/MastewalB/behemoth/utils"
)

type InternalAdapter struct {
	DB behemoth.Database
}

func (adapter *InternalAdapter) CreateUser(ctx context.Context, modelType behemoth.Model, user behemoth.M) (behemoth.User, error) {

	user["id"] = utils.GenerateUUID()
	user["created_at"] = utils.CurrentTimestamp()
	user["updated_at"] = utils.CurrentTimestamp()

	m := modelType.New()
	if serialized, ok := m.(behemoth.Serializable); ok {
		if err := serialized.FromMap(user); err != nil {
			return nil, err
		}
	}

	err := adapter.DB.Create(ctx, m)
	if err != nil {
		return nil, err
	}

	return m.(behemoth.User), nil
}

func (adapter *InternalAdapter) FindUserByID(ctx context.Context, model behemoth.Model, id any) (behemoth.User, error) {
	whereClause := clause.Expression{
		Conditions: []clause.Condition{
			{
				Field:    model.PrimaryKeyName(),
				Operator: clause.OpEqual,
				Value:    id,
			},
		},
	}

	found, err := adapter.DB.FindOne(ctx, model, whereClause)
	if err != nil {
		return nil, err
	}

	return found.(behemoth.User), nil
}

func (adapter *InternalAdapter) UpdateUser(ctx context.Context, user behemoth.Model) (behemoth.User, error) {
	err := adapter.DB.Update(ctx, user)
	if err != nil {
		return nil, err
	}

	return user.(behemoth.User), nil
}

func (adapter *InternalAdapter) DeleteUser(ctx context.Context, user behemoth.Model) error {
	return adapter.DB.Delete(ctx, user)
}

// CreateSession
// FindSession
// UpdateSession
// DeleteSession
