package adapters

import (
	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
)

// ExpectOneRow maps the rows-affected count of an operation that targets a
// specific row — Update, UpdateOne, Delete, DeleteOne — onto the
// behemoth.Database convention: NotFound when no row matched. op names the
// operation in the error.
//
// Deletes always report the rows they removed. Updates are where drivers
// differ: some report changed rather than matched rows — MySQL by default,
// and whatever dialect GORM or bun sits on — so 0 can also mean "matched, but
// already held these values". For those, countMatching (rows matching the
// update's expression) is consulted when affected is 0: a match means the
// update did apply. That keeps guarded writes correct too: a writer that lost
// the race re-counts with its own guard and finds nothing, provided the count
// reads committed data: inside a MySQL transaction a plain SELECT reads the
// transaction's snapshot, so the MySQL adapter counts with FOR SHARE. Pass nil
// when the driver reports matched rows (SQLite, Postgres, SQL Server).
func ExpectOneRow(op string, m behemoth.Model, affected int64, countMatching func() (int64, error)) error {
	if affected > 0 {
		return nil
	}
	if countMatching != nil {
		n, err := countMatching()
		if err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
	}
	return behemotherr.NewNotFound(op, m.SchemaName(), nil)
}

// ByPrimaryKey is the expression selecting m's own row.
func ByPrimaryKey(m behemoth.Model) clause.Expression {
	return clause.Expression{Conditions: []clause.Condition{
		{Field: m.PrimaryKeyName(), Operator: clause.OpEqual, Value: m.PrimaryKeyField()},
	}}
}
