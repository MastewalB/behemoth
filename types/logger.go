package types

// Logger is the logging interface plugins use. It is intentionally minimal —
// plugins should not be coupled to any specific library.
// The behemoth user wires in their preferred logger via CoreOptions.
//
// Fields are key-value pairs: logger.Info("user created", "id", u.ID, "email", u.Email)
type Logger interface {
	Debug(msg string, fields ...any)
	Info(msg string, fields ...any)
	Warn(msg string, fields ...any)
	Error(msg string, fields ...any)
}

// noopLogger is used when the caller does not provide a logger.
// And to make sure that Plugins always get a valid Logger.
type NoOpLogger struct{}

func (NoOpLogger) Debug(_ string, _ ...any) {}
func (NoOpLogger) Info(_ string, _ ...any)  {}
func (NoOpLogger) Warn(_ string, _ ...any)  {}
func (NoOpLogger) Error(_ string, _ ...any) {}
