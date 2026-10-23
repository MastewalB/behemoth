module github.com/go-behemoth/behemoth/telemetry/adapters/otel

go 1.26.0

require (
	github.com/go-behemoth/behemoth v0.0.0
	go.opentelemetry.io/otel v1.19.0
	go.opentelemetry.io/otel/metric v1.19.0
	go.opentelemetry.io/otel/trace v1.19.0
)

require (
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
)

replace github.com/go-behemoth/behemoth => ../../../
