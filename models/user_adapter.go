package models

import (
	"context"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
)

func CreateUser(ctx context.Context, db behemoth.Database, userModel behemoth.Model) (behemoth.User, error) {
	err := db.Create(ctx, userModel)
	if err != nil {
		return nil, err
	}

	return userModel.(behemoth.User), nil
}

func FindUserByID(ctx context.Context, db behemoth.Database, userModel behemoth.Model, id any) (behemoth.User, error) {
	whereClause := clause.Expression{
		Logic: clause.OpAnd,
		Conditions: []clause.Condition{
			{Field: userModel.PrimaryKeyName(), Operator: clause.OpEqual, Value: id},
		},
	}
	found, err := db.FindOne(ctx, userModel, whereClause)
	if err != nil {
		return nil, err
	}

	return found.(behemoth.User), nil
}

func FindUser(ctx context.Context, db behemoth.Database, userModel behemoth.Model, key string, value any) (behemoth.User, error) {
	whereClause := clause.Expression{
		Logic: clause.OpAnd,
		Conditions: []clause.Condition{
			{Field: key, Operator: clause.OpEqual, Value: value},
		},
	}
	found, err := db.FindOne(ctx, userModel, whereClause)
	if err != nil {
		return nil, err
	}

	return found.(behemoth.User), nil
}

func UpdateUser(ctx context.Context, db behemoth.Database, userModel behemoth.Model) (behemoth.User, error) {
	err := db.Update(ctx, userModel)
	if err != nil {
		return nil, err
	}

	return userModel.(behemoth.User), nil
}

func DeleteUser(ctx context.Context, db behemoth.Database, userModel behemoth.Model) error {
	return db.Delete(ctx, userModel)
}
