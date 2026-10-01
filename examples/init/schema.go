package main

import (
	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/types/schema"
)

// Todo is an application-owned table. Its canonical name is "todos", but it
// lives physically in "app_todos" with "title" stored as "todo_title" —
// the SchemaResolver built by Prepare is what makes the Postgres adapter
// and the migration driver both agree on that.
type Todo struct {
	ID    string
	Title string
	Done  bool
}

func (t *Todo) SchemaName() string     { return "todos" }
func (t *Todo) PrimaryKeyName() string { return "id" }
func (t *Todo) PrimaryKeyField() any   { return t.ID }
func (t *Todo) New() behemoth.Model    { return &Todo{} }

func declareAppSchema(reg schema.Registry) error {
	return reg.Declare(&Todo{}, schema.Table{
		Name:         "todos",
		PhysicalName: "app_todos",
		Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeUuid, PrimaryKey: true},
			{Name: "title", PhysicalName: "todo_title", Type: schema.ColTypeString, Length: 255},
			{Name: "done", Type: schema.ColTypeBoolean, Default: false},
		},
	})
}
