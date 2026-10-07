package store

import (
	"context"
	"errors"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/telemetry"
)

// WithTelemetry measures and traces every database operation the Store
// makes. With a metrics sink, each operation reports its duration
// (telemetry.MetricStoreDuration) and, when it fails, an error count by
// category (telemetry.MetricStoreErrors). With a tracer, each operation is a
// span named telemetry.SpanStorePrefix plus the operation.
//
// Both wrap the Store's adapter, so they cover every method of the Store
// without any of them knowing, operations inside a transaction included.
// Store.DB returns the wrapped adapter: what a plugin does through it is
// measured and traced too, and it can't be type-asserted back to the adapter
// the application built.
//
// A Telemetry with neither a metrics sink nor a tracer leaves the adapter
// unwrapped.
func WithTelemetry(tel *telemetry.Telemetry) Option { return func(s *Store) { s.tel = tel } }

// instrumented returns db wrapped to report to tel, or db itself when tel
// has nowhere to report to.
func instrumented(db behemoth.Database, tel *telemetry.Telemetry) behemoth.Database {
	if !tel.MetricsEnabled() && !tel.TracingEnabled() {
		return db
	}
	if _, already := db.(*instrumentedDB); already {
		return db
	}
	return &instrumentedDB{db: db, tel: tel}
}

// instrumentedDB is a behemoth.Database that reports each call to the
// metrics sink and the tracer, and passes it on unchanged.
type instrumentedDB struct {
	db  behemoth.Database
	tel *telemetry.Telemetry
}

var _ behemoth.Database = (*instrumentedDB)(nil)

// run executes one operation inside a span and records its duration. fn
// receives the span's context, so the driver's own instrumentation, and for
// a transaction every operation inside it, nests under the span.
//
// A NotFound from a lookup is an error here too. The error category
// attribute tells it apart from a failure of the database, and the span is
// not marked as failed for it (telemetry.FinishSpan).
func (d *instrumentedDB) run(ctx context.Context, op, entity string, fn func(ctx context.Context) error) error {
	start := time.Now()
	var spanAttrs behemoth.M
	if d.tel.TracingEnabled() && entity != "" { // a transaction has no entity
		spanAttrs = behemoth.M{telemetry.AttrEntity: entity}
	}
	spanCtx, span := d.tel.StartSpan(ctx, telemetry.SpanStorePrefix+op, spanAttrs)
	err := fn(spanCtx)
	telemetry.FinishSpan(span, err)

	if !d.tel.MetricsEnabled() {
		return err
	}
	d.tel.ObserveSince(ctx, telemetry.MetricStoreDuration, start, behemoth.M{telemetry.AttrOp: op, telemetry.AttrEntity: entity})
	if err != nil {
		category := "unknown"
		if de, ok := errors.AsType[*behemotherr.DomainError](err); ok {
			category = string(de.Category)
		}
		d.tel.Count(ctx, telemetry.MetricStoreErrors, behemoth.M{
			telemetry.AttrOp: op, telemetry.AttrEntity: entity, telemetry.AttrErrorCategory: category,
		})
	}
	return err
}

func (d *instrumentedDB) Create(ctx context.Context, m behemoth.Model) error {
	return d.run(ctx, "create", m.SchemaName(), func(ctx context.Context) error { return d.db.Create(ctx, m) })
}

func (d *instrumentedDB) FindOne(ctx context.Context, m behemoth.Model, expr clause.Expression) (found behemoth.Model, err error) {
	err = d.run(ctx, "find_one", m.SchemaName(), func(ctx context.Context) error {
		found, err = d.db.FindOne(ctx, m, expr)
		return err
	})
	return found, err
}

func (d *instrumentedDB) FindMany(ctx context.Context, m behemoth.Model, expr clause.Expression, options *behemoth.QueryOptions) (found []behemoth.Model, err error) {
	err = d.run(ctx, "find_many", m.SchemaName(), func(ctx context.Context) error {
		found, err = d.db.FindMany(ctx, m, expr, options)
		return err
	})
	return found, err
}

func (d *instrumentedDB) Update(ctx context.Context, m behemoth.Model) error {
	return d.run(ctx, "update", m.SchemaName(), func(ctx context.Context) error { return d.db.Update(ctx, m) })
}

func (d *instrumentedDB) UpdateOne(ctx context.Context, m behemoth.Model, expr clause.Expression, updates behemoth.M) error {
	return d.run(ctx, "update_one", m.SchemaName(), func(ctx context.Context) error { return d.db.UpdateOne(ctx, m, expr, updates) })
}

func (d *instrumentedDB) UpdateMany(ctx context.Context, m behemoth.Model, expr clause.Expression, updates behemoth.M) error {
	return d.run(ctx, "update_many", m.SchemaName(), func(ctx context.Context) error { return d.db.UpdateMany(ctx, m, expr, updates) })
}

func (d *instrumentedDB) Delete(ctx context.Context, m behemoth.Model) error {
	return d.run(ctx, "delete", m.SchemaName(), func(ctx context.Context) error { return d.db.Delete(ctx, m) })
}

func (d *instrumentedDB) DeleteOne(ctx context.Context, m behemoth.Model, expr clause.Expression) error {
	return d.run(ctx, "delete_one", m.SchemaName(), func(ctx context.Context) error { return d.db.DeleteOne(ctx, m, expr) })
}

func (d *instrumentedDB) DeleteMany(ctx context.Context, m behemoth.Model, expr clause.Expression) error {
	return d.run(ctx, "delete_many", m.SchemaName(), func(ctx context.Context) error { return d.db.DeleteMany(ctx, m, expr) })
}

func (d *instrumentedDB) DeleteAll(ctx context.Context, m behemoth.Model) error {
	return d.run(ctx, "delete_all", m.SchemaName(), func(ctx context.Context) error { return d.db.DeleteAll(ctx, m) })
}

func (d *instrumentedDB) Count(ctx context.Context, m behemoth.Model, expr clause.Expression) (n int64, err error) {
	err = d.run(ctx, "count", m.SchemaName(), func(ctx context.Context) error {
		n, err = d.db.Count(ctx, m, expr)
		return err
	})
	return n, err
}

// Transaction covers the whole transaction, callback included, under the
// operation "transaction" with no entity. The adapter handed to fn is
// wrapped as well, so the operations inside are reported one by one, and
// their spans are children of the transaction's.
func (d *instrumentedDB) Transaction(ctx context.Context, fn behemoth.TransactionFunc) error {
	return d.run(ctx, "transaction", "", func(ctx context.Context) error {
		return d.db.Transaction(ctx, func(txCtx context.Context, tx behemoth.Database) (any, error) {
			return fn(txCtx, instrumented(tx, d.tel))
		})
	})
}
