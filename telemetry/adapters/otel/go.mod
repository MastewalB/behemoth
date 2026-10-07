module github.com/MastewalB/behemoth/telemetry/adapters/otel

go 1.26.4

require (
	github.com/MastewalB/behemoth v0.0.0
	go.opentelemetry.io/otel v1.19.0
	go.opentelemetry.io/otel/metric v1.19.0
	go.opentelemetry.io/otel/trace v1.19.0
)

require (
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/oauth2 v0.28.0 // indirect
)

replace github.com/MastewalB/behemoth v0.0.0 => ../../../
