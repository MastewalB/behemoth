package twofactor

import (
	"context"
	"time"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/clause"
	"github.com/go-behemoth/behemoth/models"
	"github.com/go-behemoth/behemoth/schema"
)

// The tables the plugin declares. A method that is on is a row of
// MethodTable with a confirmation time; no other record says that the plugin
// is on for a user.
const (
	MethodTable       = "two_factor_methods"
	RecoveryCodeTable = "two_factor_recovery_codes"
	FailureTable      = "two_factor_failures"
)

// Columns of the plugin's tables.
const (
	colID            = "id"
	colUserID        = "user_id"
	colMethod        = "method"
	colDestination   = "destination"
	colSecret        = "secret"
	colPendingSecret = "pending_secret"
	colLastStep      = "last_step"
	colConfirmedAt   = "confirmed_at"
	colCodeHash      = "code_hash"
	colKeyVersion    = "key_version"
	colUsedAt        = "used_at"
	colFailures      = "consecutive_failures"
	colCreatedAt     = "created_at"
	colUpdatedAt     = "updated_at"
)

// methodRow is a row of two_factor_methods: one method of one user.
type methodRow struct {
	ID          string
	UserID      string
	Method      Method
	Destination string // the address or number codes go to; empty for TOTP
	// Secret is the TOTP secret, sealed with Store.Seal; empty until the
	// first confirmation. PendingSecret is a secret being set up, which a
	// confirmation moves to Secret.
	Secret        string
	PendingSecret string
	LastStep      int64      // the time step of the last TOTP code that passed; 0 for none
	ConfirmedAt   *time.Time // nil while the method is set up for the first time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (r *methodRow) SchemaName() string     { return MethodTable }
func (r *methodRow) PrimaryKeyName() string { return colID }
func (r *methodRow) PrimaryKeyField() any   { return r.ID }
func (r *methodRow) New() behemoth.Model    { return &methodRow{} }

// ToMap stores an empty destination or secret, a zero step, and a missing
// confirmation as NULL.
func (r *methodRow) ToMap() (map[string]any, error) {
	return map[string]any{
		colID:            r.ID,
		colUserID:        r.UserID,
		colMethod:        string(r.Method),
		colDestination:   orNull(r.Destination),
		colSecret:        orNull(r.Secret),
		colPendingSecret: orNull(r.PendingSecret),
		colLastStep:      stepOrNull(r.LastStep),
		colConfirmedAt:   timeOrNull(r.ConfirmedAt),
		colCreatedAt:     r.CreatedAt,
		colUpdatedAt:     r.UpdatedAt,
	}, nil
}

func (r *methodRow) FromMap(m map[string]any) error {
	r.ID, _ = m[colID].(string)
	r.UserID, _ = m[colUserID].(string)
	method, _ := m[colMethod].(string)
	r.Method = Method(method)
	r.Destination, _ = m[colDestination].(string)
	r.Secret, _ = m[colSecret].(string)
	r.PendingSecret, _ = m[colPendingSecret].(string)
	r.LastStep = int64Of(m[colLastStep])
	r.ConfirmedAt = nil
	if t, ok := m[colConfirmedAt].(time.Time); ok {
		r.ConfirmedAt = &t
	}
	r.CreatedAt, _ = m[colCreatedAt].(time.Time)
	r.UpdatedAt, _ = m[colUpdatedAt].(time.Time)
	return nil
}

// recoveryCodeRow is a row of two_factor_recovery_codes: one recovery code
// of one user, of which only a keyed hash is stored.
type recoveryCodeRow struct {
	ID         string
	UserID     string
	CodeHash   string
	KeyVersion int
	UsedAt     *time.Time // nil until the code is used
	CreatedAt  time.Time
}

func (r *recoveryCodeRow) SchemaName() string     { return RecoveryCodeTable }
func (r *recoveryCodeRow) PrimaryKeyName() string { return colID }
func (r *recoveryCodeRow) PrimaryKeyField() any   { return r.ID }
func (r *recoveryCodeRow) New() behemoth.Model    { return &recoveryCodeRow{} }

func (r *recoveryCodeRow) ToMap() (map[string]any, error) {
	return map[string]any{
		colID:         r.ID,
		colUserID:     r.UserID,
		colCodeHash:   r.CodeHash,
		colKeyVersion: r.KeyVersion,
		colUsedAt:     timeOrNull(r.UsedAt),
		colCreatedAt:  r.CreatedAt,
	}, nil
}

func (r *recoveryCodeRow) FromMap(m map[string]any) error {
	r.ID, _ = m[colID].(string)
	r.UserID, _ = m[colUserID].(string)
	r.CodeHash, _ = m[colCodeHash].(string)
	r.KeyVersion = int(int64Of(m[colKeyVersion]))
	r.UsedAt = nil
	if t, ok := m[colUsedAt].(time.Time); ok {
		r.UsedAt = &t
	}
	r.CreatedAt, _ = m[colCreatedAt].(time.Time)
	return nil
}

// failureRow is a row of two_factor_failures: the failed second factors of
// one user since the last one that passed. The row exists only after a
// failure, and a second factor that passes deletes it.
type failureRow struct {
	UserID    string
	Failures  int
	UpdatedAt time.Time
}

func (r *failureRow) SchemaName() string     { return FailureTable }
func (r *failureRow) PrimaryKeyName() string { return colUserID }
func (r *failureRow) PrimaryKeyField() any   { return r.UserID }
func (r *failureRow) New() behemoth.Model    { return &failureRow{} }

func (r *failureRow) ToMap() (map[string]any, error) {
	return map[string]any{colUserID: r.UserID, colFailures: r.Failures, colUpdatedAt: r.UpdatedAt}, nil
}

func (r *failureRow) FromMap(m map[string]any) error {
	r.UserID, _ = m[colUserID].(string)
	r.Failures = int(int64Of(m[colFailures]))
	r.UpdatedAt, _ = m[colUpdatedAt].(time.Time)
	return nil
}

// tables are the plugin's tables with their models. Each row references a
// user and goes with the user: by the foreign key's cascade where it is
// enforced, and by onUserDelete everywhere.
func tables() []struct {
	model behemoth.Model
	table schema.Table
} {
	references := func(name string) []schema.ForeignKey {
		return []schema.ForeignKey{{
			Name: name, Columns: []string{colUserID},
			RefTable: models.UserTable, RefColumns: []string{models.UserID}, OnDelete: schema.FKCascade,
		}}
	}
	return []struct {
		model behemoth.Model
		table schema.Table
	}{
		{&methodRow{}, schema.Table{
			Name: MethodTable,
			Columns: []schema.Column{
				{Name: colID, Type: schema.ColTypeString, Length: 36, PrimaryKey: true},
				{Name: colUserID, Type: schema.ColTypeString, Length: 36},
				{Name: colMethod, Type: schema.ColTypeString, Length: 16},
				{Name: colDestination, Type: schema.ColTypeString, Length: 255, Nullable: true},
				{Name: colSecret, Type: schema.ColTypeText, Nullable: true},
				{Name: colPendingSecret, Type: schema.ColTypeText, Nullable: true},
				{Name: colLastStep, Type: schema.ColTypeBigInt, Nullable: true},
				{Name: colConfirmedAt, Type: schema.ColTypeTimestamp, Nullable: true},
				{Name: colCreatedAt, Type: schema.ColTypeTimestamp},
				{Name: colUpdatedAt, Type: schema.ColTypeTimestamp},
			},
			Indexes:     []schema.Index{{Name: "uq_two_factor_methods_user_method", Columns: []string{colUserID, colMethod}, Unique: true}},
			ForeignKeys: references("fk_two_factor_methods_user"),
		}},
		{&recoveryCodeRow{}, schema.Table{
			Name: RecoveryCodeTable,
			Columns: []schema.Column{
				{Name: colID, Type: schema.ColTypeString, Length: 36, PrimaryKey: true},
				{Name: colUserID, Type: schema.ColTypeString, Length: 36},
				{Name: colCodeHash, Type: schema.ColTypeText},
				{Name: colKeyVersion, Type: schema.ColTypeInteger},
				{Name: colUsedAt, Type: schema.ColTypeTimestamp, Nullable: true},
				{Name: colCreatedAt, Type: schema.ColTypeTimestamp},
			},
			Indexes:     []schema.Index{{Name: "idx_two_factor_recovery_codes_user_id", Columns: []string{colUserID}}},
			ForeignKeys: references("fk_two_factor_recovery_codes_user"),
		}},
		{&failureRow{}, schema.Table{
			Name: FailureTable,
			Columns: []schema.Column{
				{Name: colUserID, Type: schema.ColTypeString, Length: 36, PrimaryKey: true},
				{Name: colFailures, Type: schema.ColTypeInteger},
				{Name: colUpdatedAt, Type: schema.ColTypeTimestamp},
			},
			ForeignKeys: references("fk_two_factor_failures_user"),
		}},
	}
}

// byUser selects the rows of userID.
func byUser(userID string) clause.Expression {
	return clause.Expression{Conditions: []clause.Condition{{Field: colUserID, Operator: clause.OpEqual, Value: userID}}}
}

// methodsOf returns userID's rows of two_factor_methods, confirmed or not.
func methodsOf(ctx context.Context, db behemoth.Database, userID string) ([]*methodRow, error) {
	found, err := db.FindMany(ctx, &methodRow{}, byUser(userID), nil)
	if err != nil {
		return nil, err
	}
	rows := make([]*methodRow, 0, len(found))
	for _, f := range found {
		rows = append(rows, f.(*methodRow))
	}
	return rows, nil
}

// methodOf returns userID's row for method, or a NotFound error.
func methodOf(ctx context.Context, db behemoth.Database, userID string, method Method) (*methodRow, error) {
	found, err := db.FindOne(ctx, &methodRow{}, clause.Expression{Logic: clause.OpAnd, Conditions: []clause.Condition{
		{Field: colUserID, Operator: clause.OpEqual, Value: userID},
		{Field: colMethod, Operator: clause.OpEqual, Value: string(method)},
	}})
	if err != nil {
		return nil, err
	}
	return found.(*methodRow), nil
}

// confirmedOf returns the methods of rows that are on.
func confirmedOf(rows []*methodRow) []*methodRow {
	var on []*methodRow
	for _, r := range rows {
		if r.ConfirmedAt != nil {
			on = append(on, r)
		}
	}
	return on
}

// unusedCodes selects userID's recovery codes that are not used.
func unusedCodes(userID string) clause.Expression {
	return clause.Expression{Logic: clause.OpAnd, Conditions: []clause.Condition{
		{Field: colUserID, Operator: clause.OpEqual, Value: userID},
		{Field: colUsedAt, Operator: clause.OpIsNull},
	}}
}

func orNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func stepOrNull(step int64) any {
	if step == 0 {
		return nil
	}
	return step
}

func timeOrNull(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

// int64Of reads an integer column in whichever width the driver returned.
func int64Of(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case int64:
		return n
	case float64: // after a JSON round trip
		return int64(n)
	}
	return 0
}
