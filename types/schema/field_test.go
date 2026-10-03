package schema_test

import (
	"errors"
	"testing"
	"time"

	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/types/schema"
)

type plan string

func TestFieldConvertsDriverValues(t *testing.T) {
	u := &models.User{}
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	u.SetExtra("b_int", int64(1))        // SQLite stores booleans as 0/1
	u.SetExtra("b_text", []byte("true")) // some drivers return text as bytes
	u.SetExtra("n_float", float64(42))   // a JSON round trip turns numbers into float64
	u.SetExtra("n_text", "7")            //
	u.SetExtra("s_bytes", []byte("pro")) // into a named string type
	u.SetExtra("f_int", int64(3))        //
	u.SetExtra("t_text", at.Format(time.RFC3339Nano))
	u.SetExtra("null", nil)

	check := func(name string, got any, ok bool, err error, want any) {
		t.Helper()
		if err != nil || !ok || got != want {
			t.Errorf("%s: got %#v ok=%v err=%v, want %#v", name, got, ok, err, want)
		}
	}
	b1, ok, err := schema.Field[bool]{Table: "users", Name: "b_int"}.Get(u)
	check("bool from int64", b1, ok, err, true)
	b2, ok, err := schema.Field[bool]{Table: "users", Name: "b_text"}.Get(u)
	check("bool from bytes", b2, ok, err, true)
	n1, ok, err := schema.Field[int]{Table: "users", Name: "n_float"}.Get(u)
	check("int from float64", n1, ok, err, 42)
	n2, ok, err := schema.Field[int64]{Table: "users", Name: "n_text"}.Get(u)
	check("int64 from text", n2, ok, err, int64(7))
	p, ok, err := schema.Field[plan]{Table: "users", Name: "s_bytes"}.Get(u)
	check("named string from bytes", p, ok, err, plan("pro"))
	f, ok, err := schema.Field[float64]{Table: "users", Name: "f_int"}.Get(u)
	check("float from int64", f, ok, err, float64(3))
	tm, ok, err := schema.Field[time.Time]{Table: "users", Name: "t_text"}.Get(u)
	if err != nil || !ok || !tm.Equal(at) {
		t.Errorf("time from text: got %v ok=%v err=%v", tm, ok, err)
	}

	if _, ok, err := (schema.Field[bool]{Table: "users", Name: "missing"}).Get(u); ok || err != nil {
		t.Errorf("absent: ok=%v err=%v, want false, nil", ok, err)
	}
	if _, ok, err := (schema.Field[bool]{Table: "users", Name: "null"}).Get(u); ok || err != nil {
		t.Errorf("NULL: ok=%v err=%v, want false, nil", ok, err)
	}
	if _, _, err := (schema.Field[int]{Table: "users", Name: "b_text"}).Get(u); err == nil {
		t.Error("an unconvertible value must be an error")
	}
	if _, _, err := (schema.Field[int]{Table: "sessions", Name: "n_text"}).Get(u); err == nil {
		t.Error("a field of another table must be an error")
	}
}

// Decode/Encode replace the built-in conversions: the per-column codec for a
// type no driver maps (an enum, a database-specific type).
func TestFieldCodec(t *testing.T) {
	type mood int
	const happy mood = 1
	moodField := schema.Field[mood]{
		Table: "users", Name: "mood",
		Decode: func(raw any) (mood, error) {
			if raw == "happy" {
				return happy, nil
			}
			return 0, errors.New("unknown mood")
		},
		Encode: func(m mood) (any, error) {
			if m == happy {
				return "happy", nil
			}
			return nil, errors.New("unknown mood")
		},
	}
	u := &models.User{}
	if err := moodField.Set(u, happy); err != nil {
		t.Fatal(err)
	}
	if u.Extras()["mood"] != "happy" {
		t.Errorf("stored %#v, want the encoded value", u.Extras()["mood"])
	}
	got, ok, err := moodField.Get(u)
	if err != nil || !ok || got != happy {
		t.Errorf("got %v ok=%v err=%v", got, ok, err)
	}
	changes, err := moodField.Update(happy)
	if err != nil || changes["mood"] != "happy" {
		t.Errorf("Update = %v, %v", changes, err)
	}
	if _, err := moodField.Update(0); err == nil {
		t.Error("an Encode error must surface")
	}
}

func TestFieldContribution(t *testing.T) {
	c := schema.Field[bool]{Table: "users", Name: "two_factor_enabled"}.Contribution(schema.Column{Type: schema.ColTypeBoolean})
	if c.Table != "users" || c.Column.Name != "two_factor_enabled" || c.Column.Type != schema.ColTypeBoolean {
		t.Errorf("Contribution = %+v", c)
	}
}
