# Changelog

All notable changes to Behemoth are listed here. Each release has one section, and the section at the top, "Unreleased", collects the changes that are not released yet.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Under each version, changes are grouped as Added, Changed, Deprecated, Removed, Fixed, and Security. A version heading has the form `## [0.2.0] - 2026-11-01`.

## Versioning policy

Behemoth uses [semantic versioning](https://semver.org/) with the `v` prefix that Go modules require, such as `v0.2.0`.

### Before v1.0.0

- A `v0.x` release can change the API between minor versions. For example, `v0.3.0` can remove or rename something that exists in `v0.2.0`.
- Each such change is listed in this file under "Changed" or "Removed", so that you can read it before you upgrade.
- A patch release, such as `v0.2.1`, fixes bugs and doesn't change the API.
- Pin the version in your `go.mod` and read this file before you raise it.

### From v1.0.0

`v1.0.0` starts the compatibility promise. From then on, a change that breaks the API needs a new major version.

### Modules and lockstep versions

Behemoth is one repository with several Go modules. These modules are published, and each has its own `go get` path:

| Module | Path |
| --- | --- |
| Core | `github.com/go-behemoth/behemoth` |
| Storage adapters | `github.com/go-behemoth/behemoth/storage/adapters/NAME` |
| Router adapters | `github.com/go-behemoth/behemoth/plugins/adapters/NAME` |
| Telemetry adapters | `github.com/go-behemoth/behemoth/telemetry/adapters/NAME` |

NAME is the adapter's directory name, such as `postgres`, `gin`, or `otel`.

Every release gives all published modules the same version. If you use the `postgres` storage adapter at `v0.2.0`, the matching core module is also `v0.2.0`. An adapter that has no change in a release still gets the new version number. Use one version for every Behemoth module in your `go.mod`.

The `tests/` and `examples/` modules in the repository are not published. They have no versions, and you can't install them.

### Tags

Releases are tagged on the `dev` branch until `v1.0.0`, and on `main` after it. Go resolves a tag on any branch, so you don't need to select a branch to install a version.

A tag names a version of one module:

- The core module is tagged `v0.2.0`.
- An adapter is tagged with its directory in front of the version, such as `storage/adapters/postgres/v0.2.0`.

Tags are never moved or deleted after they are pushed.

## Unreleased

### Added

- [Supported databases](docs/api/supported-databases.md) lists the minimum release of each database and the releases the tests run on: PostgreSQL 15, MySQL 8.4, SQL Server 2019, MongoDB 7.0, Redis 6.2 and SQLite 3.53.

### Security

- The SQLite adapter requires `github.com/mattn/go-sqlite3` v1.14.52, which compiles in SQLite 3.53.4. The earlier requirement, v1.14.22, compiled in SQLite 3.45.1, which lacks the fixes for several memory-corruption vulnerabilities reported in 2025 and 2026.

### Changed

- The module path changes from `github.com/MastewalB/behemoth` to `github.com/go-behemoth/behemoth`, and so does the path of every adapter module. Replace the old path with the new one in your imports and in your `go.mod`.
- The OpenTelemetry instrumentation scope of the `otel` adapter is now `github.com/go-behemoth/behemoth`. Update a dashboard or a filter that selects spans or metrics by the old scope name.
- The `go` line of every module is `1.26.0`, the oldest Go release Behemoth supports. Earlier versions named a patch release, which made `go` fetch that exact toolchain. Behemoth supports the two newest Go releases, and CI tests with the newest patch of each. Build your application with the newest patch release of your Go version, because the standard library receives security fixes in patch releases.
- Each adapter module requires the matching release of the core module, so `go get` installs an adapter on its own. Earlier adapter modules required a version that doesn't exist.

## Earlier versions

`v0.1.0` to `v0.1.3` were published under `github.com/MastewalB/behemoth`. That path is deprecated, and `v0.1.3` carries the deprecation notice. They have no changelog entries.
