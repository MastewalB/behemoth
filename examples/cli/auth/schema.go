package auth

import (
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/types/schema"
)

// Plan is a column the application adds to behemoth's users table. The
// application reads and writes it through this field: Plan.Get(user),
// Plan.Update("pro").
var Plan = schema.Field[string]{Table: "users", Name: "plan"}

// Note is a table of the application's own: a user's notes.
type Note struct {
	ID        string
	UserID    string
	Body      string
	CreatedAt time.Time
}

func (n *Note) SchemaName() string     { return "notes" }
func (n *Note) PrimaryKeyName() string { return "id" }
func (n *Note) PrimaryKeyField() any   { return n.ID }
func (n *Note) New() behemoth.Model    { return &Note{} }

// ToMap and FromMap make the model writable through the database adapter,
// which works on rows keyed by canonical column name.
func (n *Note) ToMap() (map[string]any, error) {
	return map[string]any{"id": n.ID, "user_id": n.UserID, "body": n.Body, "created_at": n.CreatedAt}, nil
}

func (n *Note) FromMap(row map[string]any) error {
	n.ID, _ = row["id"].(string)
	n.UserID, _ = row["user_id"].(string)
	n.Body, _ = row["body"].(string)
	n.CreatedAt, _ = row["created_at"].(time.Time)
	return nil
}

// declareSchema is the application's part of the schema. It is Go code that
// only this application's build contains, which is why the command line has
// to run inside that build to see it.
//
// Change something here and run "behemoth generate" again to get the next
// migration: a new column on notes, for example.
func declareSchema(reg schema.Registry) error {
	if err := reg.ExtendColumn(Plan.Contribution(schema.Column{
		Type: schema.ColTypeString, Length: 32, Default: "free",
	})); err != nil {
		return err
	}

	return reg.Declare(&Note{}, schema.Table{
		Name: "notes",
		Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeString, Length: 36, PrimaryKey: true},
			{Name: "user_id", Type: schema.ColTypeString, Length: 36},
			{Name: "body", Type: schema.ColTypeText},
			{Name: "created_at", Type: schema.ColTypeTimestamp},
		},
		Indexes: []schema.Index{{Name: "idx_notes_user_id", Columns: []string{"user_id"}}},
		ForeignKeys: []schema.ForeignKey{{
			Name: "fk_notes_user", Columns: []string{"user_id"},
			RefTable: "users", RefColumns: []string{"id"}, OnDelete: schema.FKCascade,
		}},
	})
}
