# syntax=docker/dockerfile:1

# The example's go.mod replaces behemoth and its adapters with paths inside
# this repository, so build from the REPOSITORY ROOT:
#
#   docker build -f examples/init/Dockerfile -t behemoth-init .
#
# Run (DATABASE_URL must be reachable from inside the container):
#
#   docker run --rm -p 8080:8080 \
#     -e DATABASE_URL='postgres://user:pass@host.docker.internal:5432/behemoth?sslmode=disable' \
#     -e BEHEMOTH_SECRET="$(openssl rand -hex 32)" \
#     --add-host=host.docker.internal:host-gateway \
#     behemoth-init                      # serve (default)
#
#   ... behemoth-init migrate [-confirm] # generate migrations into /app/migrations

FROM golang:1.26-bookworm AS build
WORKDIR /src

# Module files first, so dependency downloads are cached across source edits.
COPY go.mod go.sum ./
COPY storage/adapters/postgres/go.mod storage/adapters/postgres/go.sum storage/adapters/postgres/
COPY plugins/adapters/gin/go.mod plugins/adapters/gin/go.sum plugins/adapters/gin/
COPY telemetry/adapters/otel/go.mod telemetry/adapters/otel/go.sum telemetry/adapters/otel/
COPY examples/init/go.mod examples/init/go.sum examples/init/
RUN --mount=type=cache,target=/go/pkg/mod \
    cd examples/init && go mod download

COPY . .
# No cgo: SQLite (the only cgo dependency) lives in its own module, which a
# PostgreSQL application never imports. The binary is fully static.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    cd examples/init && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app . \
    && mkdir /out/migrations

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
# /app/migrations is owned by the nonroot user so `migrate -confirm` can write
# there; mount a volume on it to keep the generated files.
COPY --from=build --chown=65532:65532 /out/ /app/
ENV ADDR=:8080 GIN_MODE=release
EXPOSE 8080
ENTRYPOINT ["/app/app"]
CMD ["serve"]
