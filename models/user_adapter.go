package models

import (
	"context"

	"github.com/MastewalB/behemoth"
)

func CreateUser(ctx context.Context, db behemoth.Database, userModel behemoth.Model) (behemoth.User, error) {
	err := db.Create(ctx, userModel)
	if err != nil {
		return nil, err
	}

	return userModel.(behemoth.User), nil
}

func FindUserByID(ctx context.Context, db behemoth.Database, userModel behemoth.Model, id any) (behemoth.User, error) {
	found, err := db.Find(ctx, userModel, userModel.PrimaryKey()+" = ?", id)
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
