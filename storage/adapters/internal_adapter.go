package adapters

import (
	"context"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/utils"
)

type InternalAdapter struct {
	DB behemoth.Database
	KV behemoth.KeyValueStorage
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

func (adapter *InternalAdapter) FindUserByEmail(ctx context.Context, model behemoth.Model, email string) (behemoth.User, error) {
	whereClause := clause.Expression{
		Conditions: []clause.Condition{
			{
				Field:    "email",
				Operator: clause.OpEqual,
				Value:    email,
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

func (adapter *InternalAdapter) CreateSession(ctx context.Context, session behemoth.M) (*models.Session, error) {
	model := &models.Session{}

	session["id"] = utils.GenerateUUID()
	session["created_at"] = utils.CurrentTimestamp()
	session["updated_at"] = utils.CurrentTimestamp()

	m := model.New()
	if serialized, ok := m.(behemoth.Serializable); ok {
		if err := serialized.FromMap(session); err != nil {
			return nil, err
		}
	}

	err := adapter.DB.Create(ctx, m)
	if err != nil {
		return nil, err
	}

	return m.(*models.Session), nil

}

func (adapter *InternalAdapter) FindSession(ctx context.Context, id string) (*models.Session, error) {
	model := &models.Session{}
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

	return found.(*models.Session), nil
}

func (adapter *InternalAdapter) UpdateSession(ctx context.Context, session behemoth.Model) (behemoth.Model, error) {
	err := adapter.DB.Update(ctx, session)
	if err != nil {
		return nil, err
	}

	return session.(*models.Session), nil
}

func (adapter *InternalAdapter) DeleteSession(ctx context.Context, id string) error {
	model := &models.Session{}
	whereClause := clause.Expression{
		Conditions: []clause.Condition{
			{
				Field:    model.PrimaryKeyName(),
				Operator: clause.OpEqual,
				Value:    id,
			},
		},
	}

	return adapter.DB.DeleteOne(ctx, model, whereClause)
}
