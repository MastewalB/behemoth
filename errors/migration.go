package behemotherr

// Migration error codes: the Code of every *DomainError in CategoryMigration
// (see NewMigrationError). Callers branch on them with IsCode, so each value
// is part of the public contract — rename a constant freely, but never change
// its string.
const (
	// ---- Planning & generation ----

	// Nothing differs between the declared schema and the live schema/snapshot.
	ErrorCodeMigrationNothingToGenerate = "nothing_to_generate"
	// One or more plan issues have no (non-stale) decision in the resolution draft.
	ErrorCodeMigrationUnresolvedIssues = "unresolved_issues"
	// A live column's type has no mapping to a canonical ColumnType.
	ErrorCodeMigrationUnmappableColumnType = "unmappable_column_type"
	// A declared table exists live as a view or another non-table object.
	ErrorCodeMigrationIncompatibleObject = "incompatible_object"
	// Migrations depend on each other in a cycle.
	ErrorCodeMigrationDependencyCycle = "dependency_cycle"
	// The resolution draft file could not be read.
	ErrorCodeMigrationDraftReadFailed = "draft_read_failed"
	// A migration's Up could not be projected onto the snapshot.
	ErrorCodeMigrationSnapshotProjectionFailed = "snapshot_projection_failed"

	// ---- Run state (PathManaged) ----

	// A migration file exists on disk that the snapshot doesn't reflect yet.
	ErrorCodeMigrationUnappliedPending = "unapplied_migrations_pending"
	// Migration files exist but no ledger table does: no safe starting point.
	ErrorCodeMigrationUnappliedNoLedger = "unapplied_migrations_no_ledger"
	// A ledger table exists but the migration folder is empty.
	ErrorCodeMigrationLedgerWithoutFiles = "ledger_without_files"
	// More than one migration is pending where at most one is expected.
	ErrorCodeMigrationMultipleUnapplied = "multiple_unapplied_migrations"
	// A baseline awaiting confirmation no longer has any live table behind it.
	ErrorCodeMigrationBaselineCandidatesVanished = "baseline_candidates_vanished"
	// The driver failed to apply a migration.
	ErrorCodeMigrationApplyFailed = "apply_failed"

	// ---- Migration files on disk ----

	ErrorCodeMigrationMkdirFailed     = "mkdir_failed"
	ErrorCodeMigrationReadDirFailed   = "read_dir_failed"
	ErrorCodeMigrationReadFileFailed  = "read_file_failed"
	ErrorCodeMigrationWriteFailed     = "write_failed"
	ErrorCodeMigrationMarshalFailed   = "marshal_failed"
	ErrorCodeMigrationUnmarshalFailed = "unmarshal_failed"

	// ---- Rendering (MigrationRenderer) ----

	ErrorCodeMigrationRenderFailed = "render_failed"
	// A MigrationRenderer returned an empty FileExtension.
	ErrorCodeMigrationMissingFileExtension = "missing_file_extension"

	// ---- Ledger & snapshot rows ----

	ErrorCodeMigrationInvalidLedgerEntry = "invalid_ledger_entry"
	ErrorCodeMigrationInvalidSnapshot    = "invalid_snapshot"

	// ---- Introspection ----

	ErrorCodeMigrationExistenceCheckFailed = "existence_check_failed"
	ErrorCodeMigrationIntrospectionFailed  = "introspection_failed"

	// ---- Driver: schema model support ----

	// No native rendering for a canonical ColumnType.
	ErrorCodeMigrationUnsupportedCanonicalType = "unsupported_canonical_type"
	// Column.Default holds a value type that can't be rendered as a literal.
	ErrorCodeMigrationUnsupportedDefaultType = "unsupported_default_type"
	// AutoInc on a column the database can't auto-increment.
	ErrorCodeMigrationUnsupportedAutoIncrement = "unsupported_autoincrement"
	ErrorCodeMigrationInvalidIndex             = "invalid_index"
	ErrorCodeMigrationInvalidForeignKey        = "invalid_foreign_key"
	// An operation targets a table that doesn't exist.
	ErrorCodeMigrationTableNotFound = "table_not_found"

	// ---- Driver: execution ----

	ErrorCodeMigrationConnFailed     = "conn_failed"
	ErrorCodeMigrationBeginTxFailed  = "begin_tx_failed"
	ErrorCodeMigrationCommitFailed   = "commit_failed"
	ErrorCodeMigrationRollbackFailed = "rollback_failed"
	ErrorCodeMigrationLockFailed     = "lock_failed"
	ErrorCodeMigrationPragmaFailed   = "pragma_failed"
	ErrorCodeMigrationExecFailed     = "exec_failed"
	ErrorCodeMigrationQueryFailed    = "query_failed"
	ErrorCodeMigrationScanFailed     = "scan_failed"
	// Committing would leave rows that violate a foreign key.
	ErrorCodeMigrationForeignKeyViolation = "foreign_key_violation"
	// SQLite: a table's stored CREATE TABLE statement couldn't be parsed or edited for a rebuild.
	ErrorCodeMigrationParseFailed   = "parse_failed"
	ErrorCodeMigrationRebuildFailed = "rebuild_failed"
)
