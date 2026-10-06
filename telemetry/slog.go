package telemetry

import (
	"context"
	"io"
	"log/slog"
	"slices"

	"github.com/MastewalB/behemoth"
)

// NewSlogLogger returns a Logger that writes to l. It is the backend for
// stdout, and for any library with a slog.Handler (zap, zerolog). A nil l
// means slog.Default().
//
// Fields become attributes in key order, so a line's output is stable. The
// source location slog records is this adapter's, not the call site's, so
// handlers are best built without AddSource.
func NewSlogLogger(l *slog.Logger) Logger {
	if l == nil {
		l = slog.Default()
	}
	return &slogLogger{l: l}
}

// NewTextLogger returns a Logger that writes human-readable lines to w
// (os.Stdout, os.Stderr) at level and above.
func NewTextLogger(w io.Writer, level slog.Level) Logger {
	return NewSlogLogger(slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})))
}

// NewJSONLogger returns a Logger that writes one JSON object per line to w
// at level and above.
func NewJSONLogger(w io.Writer, level slog.Level) Logger {
	return NewSlogLogger(slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})))
}

type slogLogger struct{ l *slog.Logger }

func (s *slogLogger) log(ctx context.Context, level slog.Level, msg string, fields behemoth.M) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !s.l.Enabled(ctx, level) {
		return
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	attrs := make([]slog.Attr, len(keys))
	for i, k := range keys {
		attrs[i] = slog.Any(k, fields[k])
	}
	s.l.LogAttrs(ctx, level, msg, attrs...)
}

func (s *slogLogger) Debug(ctx context.Context, msg string, fields behemoth.M) {
	s.log(ctx, slog.LevelDebug, msg, fields)
}
func (s *slogLogger) Info(ctx context.Context, msg string, fields behemoth.M) {
	s.log(ctx, slog.LevelInfo, msg, fields)
}
func (s *slogLogger) Warn(ctx context.Context, msg string, fields behemoth.M) {
	s.log(ctx, slog.LevelWarn, msg, fields)
}
func (s *slogLogger) Error(ctx context.Context, msg string, fields behemoth.M) {
	s.log(ctx, slog.LevelError, msg, fields)
}
