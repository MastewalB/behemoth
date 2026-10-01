
## **Schema Migration**
This section explains what behemoth does about schema definition migration. Any information on how to migrate existing data to behemoths structure should be put in the *Data Migration* topic.

### **Two Scenarios - Based on scope**
When it comes to schema migration, there are two clear cut scenarios. One with execution and the other without. 

Why based on scope and not on greenfield vs brownfield - In both scenarios, we might find clean slate and already existing data, and more importantly, they deal with **initial integration** rather than **lifetime flow** of the component, so designing our architecture based on them is not a good choice.

## **Path I - Diff - Plan - Generate - Apply**

When behemoth is responsible for generation and execution of the schema migrations. Even though this might be rarely the case, sometimes users might just have a backend service that handles only authentication logic and user management. It's better to have the full capability instead of forcing users to introduce separate tools (like goose, golang-migrate)  

## **Path II - Diff - Plan - Generate** 

For common cases and larger services, users use dedicated tools that manage and apply migrations. In this case it's best to stop at generation and handing the rest to the tool. Since multiple modules editing and executing migration data is a bad design that leads to inconsistency and multiple failure points. 
Behemoth might provide tool-specific generation (for goose or golang-migrate for e.g.) but as a separate packaging that's optionally installed instead of crammed in the core package.


# **Introspection/Diff stage - common to both scenarios**

In this stage, the mapped schema registry is compared against the live database. This stage produces a structured description of where the live database's shape disagrees with the `SchemaRegistry`

Roughly:
Introspect -> Diff -> Report Ambiguities 

### **Pre-Step**
Before any comparison happens, every declared table/column is resolved to its `PhysicalName`. All comparison below happens in **physical (DB-side) identifier space**. 
`[Convention]` The Introspection Report itself must translate physical identifiers back to canonical `Name` before being shown to a human.

### **Note on extra entities (columns, indexes & foreign keys)**
- `[Convention]` Behemoth will not and should not manage any extra column, index, or foreign key unless the migration management is set to `PathManaged`(Path I).
- Extra objects found live are not tracked unless the `trackExtraColumns` flag is true. The flag is set to true for `PathManaged` and the objects are subject to drop operations.
#### **Branch - Table Level**

- **Declared table missing live** -> fresh table; queued as a create candidate.
- **Declared table found live** -> proceed to Column/Index/Foreign-Key branches below.
- **Non-declared extra table found live** → ignored entirely. 
	- `[Convention]` Behemoth only ever manages what is declared; an extra table is invisible to this pipeline by design.
- **Declared table exists live as an incompatible object** (e.g. it's a VIEW, not a TABLE) → 
	- `[Advanced]` treated as a hard ambiguity, surfaced as a blocking error rather than silently attempting to replace it.
	- `[Deferred]` No automatic handling in this phase. A manual intervention is required.

#### **Branch - Column Level (Within Table Found Live)**

- **Declared column found live, definition matches** (type, nullability, default, length all equivalent after native↔canonical mapping) → no action.
- **Declared column found live, definition differs** → divergence recorded (candidate alter). `[Implementation Detail]` Whether this is auto-safe or requires confirmation is decided by the Plan stage.
- **Declared column missing live** → candidate add, _unless_ it pairs with an extra live column below (see Rename Detection).
- **Non-declared extra column found live** → no action. 
	- `[Convention]` The developer's own custom columns are left untouched, provided the owning `Model` implements `Serializable`. Behemoth will persist what it's given without requiring exclusive ownership of every column.
	
- **Rename Detection** (a "declared missing" + "extra live" pair, matched by structural signature i.e. type/nullable/length equivalence) → always surfaced as an **unresolved ambiguity requiring explicit confirmation**. `[Convention, important]`

	- **Multiple equally-plausible candidates for one column** → no pairing is guessed; every involved column falls back to independent add/drop candidates, each still individually flagged for review. `[Implementation Detail]`

#### **Branch - Type Reverse-Mapping Ambiguity (Column Level)**

When the live database column type have no direct mapping to behemoth's list of supported column types, a type mapping ambiguity arises. This is out of scope for behemoth to handle, since it's not a comprehensive migration engine that's able to map every existing database types. The introspector's type support can grow over time as the need and relevance dictate, but that doesn't guarantee a complete coverage for all databases.

If a user table has such unsupported field, they should provide a custom Model type with Model + Serializer interface implementations for the schema.

#### **Branch - Index Level (within a table found live)**

Mirrors Column Level exactly: 
**Declared Index found live** → no action; 
**Declared Index found live, definition differs** (columns or uniqueness disagree) → divergence; 
**Declared Index missing live** → add candidate (additive, safe); 
**Non-declared extra Index found live** → no action, 
`[Convention]` The same rule for extra columns/tables apply here.

#### **Branch - Foreign Key Level (within a table found live)**

Same four sub-cases as Index Level: 
**Declared Foreign Key found live** → no action; 
**Declared Foreign Key found live, definition differs** (RefTable/RefColumns/OnDelete disagree ) → divergence; 
**Declared Foreign Key missing live** → add candidate (additive, safe); 
**Non-declared extra Foreign Key found live** → no action, 

### **Output of this stage**

One Introspection Report: per table, per column/index/FK  matches, divergences, and ambiguities, all keyed by canonical name. This report is an input to the Plan stage.

Notes
- `[Convention, important]` Since introspection is now required for _both_ paths, `SchemaIntrospector` is a **required** driver capability for migration support.


### Introspection frequency by Path

- **Path I** → Introspection required **once**, at onboarding (Baseline/Adopt) only. After baseline, behemoth's own ledger + snapshot are authoritative for "previous," and standing `generate` calls diff the canonical-snapshot-vs-canonical-current without a live DB introspection. `[Convention]`
- **Path II** → Introspection required **on every `generate` call**, since behemoth never applies anything and therefore never owns a ledger telling it what's actually live. Live reality is the only trustworthy "previous." `[Convention, important]`

#### `[Advanced]` Avoiding introspection on every call, for Path II

**Proposed mechanism — trusted, fingerprint-verified snapshot cache**, not a way to skip verification entirely:

- A one-time explicit command (e.g. `behemoth schema snapshot`) performs a real introspection and writes the result to a file the developer commits to their repository (`.behemoth/schema-cache.json`) The file serves as a **cache**, and behemoth will not write to it automatically.
- On a subsequent `generate` call, behemoth runs one **cheap fingerprint check** against the live database first — table names, column counts, a lightweight checksum. If the fingerprint matches the cached file's recorded fingerprint, the cached snapshot is trusted as "previous" and full introspection is skipped. If it doesn't match, behemoth **automatically falls back to full introspection** and a warning is issued stating that the cache is stale.
- `[Convention, important]` The cache will not silently allow a drift — a mismatch always forces the safe path. A developer can force full introspection regardless of a matching fingerprint via an explicit flag, but there is no flag to force _trusting_ a cache despite a fingerprint mismatch. That direction of override is not offered, not to risk a data loss.
- `[Implementation Detail]` Fingerprint composition (which fast facts are cheap enough to check on every call vs. worth caching) is left open for the implementation pass.

**Driver without introspection capability** → `[Deferred]` fall back to the previously-designed pure canonical-snapshot diffing for that driver only, as a reduced-capability mode, rather than refusing migration support outright. Not designed in this pass.

# **Planning Stage** 

This stage converts the Introspection Report's divergences and ambiguities into a concrete, tiered list of **candidate `SchemaOperation`s** — deciding _what kind of change_ each divergence implies and _whether it's safe to auto-apply_. Plan's output is an unordered set of candidates plus their tier; Generate stage is responsible for turning that into an ordered, immutable artifact.

#### **Operation Tiers**
1. Safe/Auto - Can be applied automatically
2. Data Dependent - Affects existing data. e.g. add unique index. Resolved to either 'Safe' or 'Manual'
3. Requires Confirmation - Potential data loss. e.g. drop table
4. Manual - Should be performed manually 

### **Note on extra entities (columns, indexes & foreign keys)**
- The introspection stage has already handled extra objects found live. If any extra entities are encountered in the planning stage, it means they were part of the old schema registry and are now subject to drop operation after user confirmation. 

#### **Branch - Table-Level Divergences**

- **Fresh table (declared, missing live)** → `OpCreateTable` candidate. `[Tier: Auto]`. If the table has a foreign key declaration, a separate operation for the foreign key will be created for it to prevent cycle. 
- **Table found live, matches** → no candidate generated.
- **Table found live, incompatible object** (Introspection's VIEW-vs-TABLE case) `[Tier: Manual]` → blocking; no candidate generated, Plan won't proceed for that table until resolved outside the tool. `[Convention]`

#### **Branch - Column-Level Divergences**

- **Declared column missing live, no rename pairing found** → `OpAddColumn` candidate. `[Tier: Auto]`
- **Extra live column, no rename pairing found** → `OpDropColumn` candidate. `[Tier: Requires Confirmation]`. Here the extra live columns are categorized to "drop column".
		~~**Distinguishing "ignore custom field" from "op: drop column"**~~
		~~An extra live column is only turned into an `OpDropColumn` candidate if it was _previously_ declared in behemoth's own last-known canonical state (Path I's snapshot) or was explicitly flagged by the developer as behemoth-managed (Path II has no snapshot, so this case is narrower there - see Path-specific note below). A column that has _never_ been part of any behemoth-authored declaration is never turned into a drop candidate automatically, regardless of Path — this is what actually implements the "developer's custom field" convention from your original draft, rather than leaving it as an unenforced assumption. `[Convention, important]`~~

	- **Path I** → "previously declared" is answered exactly by the snapshot.
	- **Path II** → no snapshot exists, and the introspector excludes all extra columns before passing the live state to planner. 

- **Rename-paired columns** (from Introspection's structural-signature matching) → `OpRenameColumn` candidate. `[Tier: Requires Confirmation]`
- **Definition divergence** (type/nullable/default/length differ) → `OpAlterColumn` candidate. Tier determined by direction:

	- **Widening** (nullable→true, length increases, no data can be rejected) → `[Tier: Auto]`
	- **Narrowing** (any type change, nullable→false, length decreases, auto-increment added or removed, a default is removed) → `[Tier: Data Dependent]`. Every type change counts, even usually-safe ones (integer→bigint): whether existing values convert depends on data planning never reads. Both sides are compared after driver normalization (`ColumnNormalizer`), so a type the driver stores identically (uuid in SQLite's BLOB) is not a change.

- ~~**Type reverse-mapping ambiguity carried over from Introspection** → `[Convention]` Plan refuses to finalize tiering for that column until the ambiguity is resolved via the draft-review mechanism — an unresolved ambiguity is never silently defaulted to a tier.~~

#### **Branch - Index-Level Divergences**

- **Declared, missing live** → `OpAddIndex`. `[Tier: Auto]`
- **Extra live, unpaired** → `OpDropIndex`. `[Tier: Auto]`.
- **Definition differs** (columns or uniqueness disagree) → treated as drop-and-recreate (no `OpAlterIndex` kind exists) → both candidates generated together, `[Tier: Auto]` for the add half, `[Tier: Auto]` for the drop half, since dropping an index alone still can't lose row data.

#### **Branch - Foreign-Key-Level Divergences**

- **Declared, missing live** → `OpAddForeignKey`. `[Tier: Auto]`
- **Extra live, unpaired** → `OpDropForeignKey`. `[Tier: Auto]` — removes a constraint, not data.
- **Definition differs** (RefTable/RefColumns/OnDelete disagree) → drop-and-recreate, both halves `[Tier: Auto]`.

#### **Branch - Developer-Authored Custom Operations**

- A developer may inject a hand-written operation (typically a data-affecting step with no structural divergence behind it. e.g. a backfill) directly into the candidate set at Plan time. 
- `[Implementation Detail]` The mechanics of _how_ a custom operation is authored/injected (file-based, code-based) are left to the Generate-stage discussion, since a custom operation need to participate in the dependency graph.


#### **Issue Planner**

For the divergences and ambiguities identified, the full set of candidate operations are presented for resolution. 
#### Types

```go
type ResolutionOption struct {
	Label      string            // human-readable, e.g. "Rename email -> email_address"
	Operations []SchemaOperation // what accepting this option produces -> built by Planning, never by Resolution
}

type PlanIssue struct {
	ID          string // STABLE, content-derived — see Resolution's Identity Stability branch.
	Table       string
	Description string
	Options     []ResolutionOption
	Default     int // Planning's suggested option index. a hint for the presenter's default selection
}
```

`[Convention, important]` A `PlanIssue`'s `ID` is composed only from the **stable artifact the issue is about** (e.g. `table + ":dropped_column:" + columnName`). The computed pairing or option set is not included to allow separate runs to be able to propose a different set of options to a given issue even when the database state changes.

#### **Handled Issues and Their Options**

| Issue                                                             | Options offered                                                                                   |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Rename candidate (single structural match)                        | Rename · Drop old + Add new independently · Leave as-is                                           |
| Ambiguous rename (multiple equally-plausible candidates)          | Manually pair specific columns · Fall back to independent add/drop for all involved · Leave as-is |
| Narrowing alter (type change, nullable→false, length shrinks, auto-increment added or removed, default removed) | Apply alter · Apply alter with a specified default for existing rows · Leave as-is |
| ~~Type reverse-mapping ambiguity~~                                | ~~Accept Planning's guessed canonical type · Override with a specified type · Leave as-is~~       |
| Table found live as an incompatible object (view, etc.)           | _(no automated option — blocking; message directs to manual resolution outside the tool)_         |
| Extra live column, never behemoth-declared                        | _(no options — not an issue since it's never surfaced)_                                           |

`[Convention]` "Leave as-is" is a first-class option everywhere it applies. It produces zero operations and is recorded as a real decision. It is the mechanism by which a developer who resolves something manually, directly against the database, tells the system not to ask again.

#### **Output of this stage**

A flat set of candidate operations, each tagged with a tier and, where relevant, a confirmation state (resolved / unresolved). 

`[Convention]` Plan doesn't produce operation ordering — two candidates with a real dependency (e.g. a column addition on a table also being created in this same run) are both present in the output, unordered. Sequencing them correctly is explicitly out of scope here and belongs to the Generation stage.

#### **Branch - Confirmation Workflow (for every "Requires Confirmation" candidate above)**

- **Interactive context** (local developer machine) → each unresolved candidate is presented for explicit accept/reject; rejecting a proposed `OpRenameColumn` decomposes it back into independent `OpAddColumn` (auto) + `OpDropColumn` (now itself requiring its own separate confirmation).
- **Non-interactive context** (CI) → `[Convention, important]` Plan fails closed. Any unresolved "Requires Confirmation" candidate blocks the run entirely with an explicit listing — there is no default answer, ever, for a destructive or ambiguous candidate in an unattended context.
- **Multiple ambiguous rename candidates for one column** (Introspection's multi-candidate case) → surfaced as a named group in the same review mechanism; resolution requires the developer to manually pick a pairing or accept the fallback independent add/drop for all involved columns. `[Implementation Detail]`
- Output of a resolved review session is a human-editable **draft** — the same mechanism regardless of Path, and the same mechanism used later for Baseline's own review step — never an immediately-finalized artifact. `[Convention]`


# **Resolution Stage** 

This stage produces a resolved set of operations by taking the `PlanIssue` types has Planning stage generated and presenting them to the user. 

#### **Communication Medium**

Multiple candidate media exist; the design picks one default and keeps the others swappable behind a single interface.
```go
type ResolutionPresenter interface {
	// Present writes/updates whatever medium holds unresolved issues,
	// alongside decisions already made in a prior session, so a partial
	// resolution session is never silently discarded.
	Present(ctx context.Context, issues []PlanIssue, priorDecisions map[string]int) error
	// Collect reads back developer decisions, keyed by PlanIssue.ID.
	Collect(ctx context.Context) (decisions map[string]int, err error)
}
```

- **Editable draft file** _(default implementation)_ - stored on disk, git-diffable and survives process restarts. 
- **Live terminal prompt** - a thin front-end only. Every answer is written through to the same durable file immediately, never held only in process memory. 
	- `[Convention, important]` A prompt-only implementation with no backing file is explicitly disallowed, because an interrupted session must not lose already-made decisions - this is the exact failure mode observed in other tools' interactive-only flows, where an interrupted or non-interactive run has no persisted answer to fall back on.
- **Remote/shared registry** - appropriate for team-scale and multi-environment setups; not required infrastructure for a self-hosted default. `[Deferred]` A concrete implementation is not built in this phase, but the interface is shaped to accommodate one without redesign.
- **Programmatic resolver** - a developer-supplied callback resolving specific issue IDs in code, for CI automation of known/expected changes. `[Advanced]` Composes with the same interface rather than being a special case.

`[Convention, important]` Non-interactive context with any unresolved issue **fails closed**. The run is aborted with an explicit listing of every unresolved `PlanIssue.ID` and its available options. There is no default answer for a destructive or ambiguous issue in an unattended context.

#### **Execution Flow**

The `PlanIssue.ID` being **stable and content-derived**( a hash of `table, kind, involved column/index/FK names)`, can be used to track and identify tracks across multiple runs. The draft file, on disk, is a list of `{id, description, options, chosen: <index or null>}` entries. On every subsequent run:

1. Planning re-derives the current issue set fresh (Planning is a pure function and doesn't depend on any persisted state).
2. Resolution loads the _existing_ draft file, if one exists, and matches by `ID`. An issue whose `ID` already has a non-null `chosen` value in the file is treated as already-resolved and is never re-presented.
3. Only new issues (new IDs, that are not present in the old draft) get appended, pending, for the developer to address.
4. An issue whose `ID` no longer appears at all (because live state changed and the divergence is gone) is automatically dropped from the next draft.


### **Identity Stability _(edge cases)_**

`[Convention, important]` The most important correctness property of this stage: a `PlanIssue`'s `ID` must be derived from the artifact it describes, not from Planning's currently-computed resolution options. Without this, the following scenarios will fail:

#### **A Decision was not made, and the issue option set changed**

- **A pending issue's option set changes between runs** - Safe to discard the old issue and write the new one. This happens when the user manually fixes/updates the live state between runs. 
	*(e.g. a new column appears that's also a structurally plausible rename target, turning a single-candidate rename into an ambiguous one)*. 
	
  Because identity is anchored to the stable side of the divergence (the actual live-or-declared artifact), the issue's `ID` is unchanged — Resolution simply re-presents it with the newly expanded option set. No decision is lost and no issue is duplicated.

#### **A Decision was made, but the issue option set changed**
- **An already-confirmed issue's option set changes before the draft is consumed** (a new candidate appears after the developer already chose an option, but before `Generate` has run). 
	- `[Convention, important]` A confirmed decision is **sticky** — it is never silently reopened just because Planning surfaced a new candidate on a later run, since auto-reopening risks discarding a deliberate human decision. But it isn't silently ignored either. The draft instead carries a visible warning against that entry: _"resolved as X; a new candidate (Y) has since appeared — review recommended."_ The developer can explicitly reopen it; the system never does so on their behalf.
	
- **A pending issue's underlying divergence disappears entirely** (fixed manually outside the tool, or the model change was reverted). Its `ID` simply no longer appears in Planning's freshly-derived issue set on the next run and is dropped from the draft and nothing is left to reconcile.
- **ID collision across unrelated issues.** `[Convention]` Composition always includes table name and operation kind alongside the artifact name specifically to prevent two unrelated divergences in different tables from ever hashing to the same identity.

#### **Input Validation _(edge case)_**

`[Convention, important]` A hand-edited draft may contain a malformed decision — an out-of-range option index, two options marked chosen, a decision recorded against an `ID` that no longer exists in the current issue set. `Collect` must treat any such entry as **invalid and still pending**, surfaced as a reviewable error, not silently defaulted to any option, including `Default`.

#### **Draft Lifecycle _(edge case)_**

`[Convention, important]` A draft is scoped to a single generation session, not left to accumulate indefinitely. Once `Generate` successfully consumes a `ResolvedOperationSet` and freezes a `Migration`, the draft is consumed/archived — not left present for a future `generate` run to confusingly compare against, since the "previous" state has now moved forward and old resolved entries would no longer correspond to anything Planning could regenerate.

#### **Output**

`ResolvedOperationSet` — as defined in the Generate-stage manifesto. Every operation present is either auto-tiered (never required a decision) or was explicitly resolved by a human through this stage. `[Convention]` `Generate`'s function signature accepts only this type, never `MigrationPlan` or raw `PlanIssue` data, making it a compile-time error — not merely a documented expectation — to wire the pipeline in a way that bypasses Resolution.

```go
type ResolvedOperationSet struct {
	Operations []SchemaOperation
	Custom     []CustomMigration
}
```


# **Generation Stage** 

This stage generates the migration object with ordered list of schema operations.

### Overall Steps 
1. Build dependency-graph with structural and explicit edges and create topological ordering
2. Build reverse operations for each schema operation 
3. Compute Next migration ID and create the object

#### **Branch - Structural Edge Inference - Dependency Graph Building** 

- **Rule 1:** Any operation targeting table T depends on T's own `OpCreateTable`, if T is created within this same `ResolvedOperationSet`.
- **Rule 2:** `OpAddForeignKey` depends on its `RefTable`'s `OpCreateTable`, if `RefTable` is created within this same set.
- **Rule 3:** `OpDropForeignKey` must precede its `RefTable`'s `OpDropTable`, if both exist within this same set.
- **Rule 4:** Explicitly declared dependencies in `SchemaOperations` & `CustomMigration` are added.

##### **Dependency ordering / deferred constraint creation problem**

The dependency ordering logic should support logically valid cyclic dependencies, such as two tables with foreign keys referencing each other. Naively creating each table with its foreign key constraint can fail because neither table can be created before the other. Instead, the generator should create all cyclic tables without their foreign key constraints first, then add those constraints afterward using `ALTER TABLE`. This allows both tables to be created successfully while preserving the intended foreign key relationships.
	***The fix - Put Foreign Key declarations separate from `CreateTable`** - The planner will put the two operations separately.*  **`OpCreateTable` will not carry foreign keys in its `NewTable.ForeignKeys`.**

#### **Branch - Explicit Edge Declaration**

`SchemaOperation.DependsOn` / `CustomMigration.DependsOn` — the escape hatch for anything with no structural signal (a data backfill ordered relative to an unrelated table).

#### **Branch - Mutual Table Reference**

**Handled, in scope:**

- Two (or more) tables whose only interdependency is via foreign keys → resolved automatically per Rule 4, with zero developer intervention. Output ordering: `CreateTable(A)`, `CreateTable(B)` (relative order between these two is now a tie, broken by the existing alphabetical/registration-order tiebreak, then `AddForeignKey(A->B)`, `AddForeignKey(B->A)` in whichever order their own dependencies resolve.
- **N-table mutual reference cycles** (A->B->C->A) → handled by the identical mechanism, since Rule 4 makes _every_ FK edge point only at a `CreateTable`, never at another FK — a cycle among FK operations themselves cannot form regardless of how many tables are involved. `[Convention]`

**Explicitly out of scope, documented for future reference:**

- **`[Deferred]`** The generator doesn't handle a pair of mutually dependent NOT NULL foreign-key columns when neither side can initially contain a valid reference. Therefore, either a multi-step migration that temporarily allows NULLs, or database-specific support for deferred foreign-key constraints(`DEFERRABLE INITIALLY DEFERRED` in Postgres) is required.
	- A good example: Assuming there are two tables `users` and `profiles`, Every `users` row must point to an existing `profiles` row, **and** every `profiles` row must point to an existing `users` row.
	
- **`[Deferred]` Circular dependencies through custom/manual migrations** — e.g. a hand-authored data migration that depends on a table which itself indirectly depends (via `DependsOn`) back on that same custom migration. Since `DependsOn` is explicit and developer-authored, a cycle here is a **developer authoring error**, not a structural inevitability like the FK case — Generate's job is only to **detect and report it clearly** (via the existing `KahnSort` cycle-path reporting), never to silently resolve it. `[Convention]`

- **`[Deferred]` Circular check constraints or triggers referencing each other across tables** — genuinely rare, dialect-heavy, and not addressed by this design at all in the current phase.

- **`[Deferred]` Self-referencing single-table foreign keys** (a table with a FK to itself, e.g. an `employees.manager_id → employees.id` hierarchy) — this is **not actually a cycle** in the graph sense (Rule 1 already handles it: the FK operation depends on the table's own `CreateTable`, which necessarily precedes it, no different-table dependency exists at all), but worth explicitly documenting as a _non-issue_ so it's never mistaken for one of the deferred cases above. `[Convention]`

`[Question, resolved]` — "should Generate attempt to resolve every theoretically possible cyclic schema"? No. The single-rule fix (FKs are never inline) resolves the one realistic, common case (mutual/circular table references) completely and generically, without needing cycle-detection-and-repair logic in the graph algorithm itself. Anything beyond that — the four deferred cases above — is rare enough, and dialect-specific enough, that hand-authoring a `CustomMigration` with explicit `DependsOn` is the correct escape hatch, not a feature to generalize now.

### **Branch - Reverse Operation Construction (`Down`)**

- Down is computed by walking the finalized `Up` ordering **in reverse** and inverting each operation (`invertOperation`) — `OpCreateTable - OpDropTable`, `OpAddColumn - OpDropColumn` (using the retained prior definition), `OpRenameColumn` swaps its two names, `OpAlterColumn` reverts to `PrevColumn`, `OpAddIndex/FK - OpDrop*`.

- **`[Convention, important]` All-or-nothing reversibility,:** if any single step in `Up` cannot be inverted (a `CustomMigration` with no authored `Down`, a retained-definition field unexpectedly missing), the **entire** migration's `Down` is `nil` to prevent a partial rollback stopping midway.

- **Mutual-FK case, specifically:** inverting the deferred-constraint sequence is naturally symmetric and requires no special handling — `Down` of `[CreateTable(A), CreateTable(B), AddFK(A->B), AddFK(B->A)]` is simply `[DropFK(B->A), DropFK(A->B), DropTable(B), DropTable(A)]`, which is itself correctly ordered by the same reversal, and satisfies Rule 3 (`DropForeignKey` before its `RefTable`'s `DropTable`) automatically. `[Convention]` No additional rule is needed for reversing the deferred-constraint pattern — straight reversal of a correctly-ordered forward sequence is always itself correctly ordered backward, given Rules 1–4 hold.


`[Convention]` `LatestMigrationID`'s limitation for `PathGenerateOnly`: if the developer has already moved a previously generated file out of `FolderPath` (per that Path's own contract — "user is responsible to put it in their desired location"), behemoth has no way to see it and will compute IDs as if that migration never existed, producing a duplicate ID on the next run. This is an accepted consequence of `PathGenerateOnly` owning no persistent record beyond the staging folder, with a possible workaround being an explicit `--previous <id>` CLI override for that mode.

# **Runner Stage — Path I _(Apply)_**

**Purpose:** the complete Path I entry point, covering both greenfield (no live tables yet) and brownfield (adopting tables that already exist live) cases under a single orchestrator. This is the stage where a schema change reaches the database by executing the DDL and write to the ledger/snapshot tables.`[Convention, important]`

### **Entry Point**

```go
func RunMigration(ctx context.Context, cfg MigrationConfig, current SchemaRegistry, deps MigrationDeps, interactive bool) (*Migration, error)
```

### **Step 0 - Precondition**

`[Convention]` Only reachable when `MigrationConfig.Path == PathManaged`. Path II will stop at Generate Stage.

### **Step 1 - Folder & Candidate Detection**

- `EnsureMigrationFolder` creates `cfg.FolderPath` if absent.
- `PartitionForBaseline` checks every table `current` declares against live existence via `SchemaIntrospector.TableExists`.
    - **No candidates found** → pure greenfield. Baseline phase is skipped entirely; control passes straight to Step 5.
    - **One or more candidates found** → brownfield adoption; Baseline Phase (Steps 2–4) runs before Step 5 is reached.

`[Convention]` Behemoth detects the current database live state automatically.
### **Baseline Phase _(Steps 2–4, brownfield only)_**

### **Step 2 - Introspection**

`RunIntrospection` runs against only the candidate tables (never the full declared set — the greenfield tables have nothing to introspect).

`[Convention]` `trackExtraColumns` is always passed as `true` in this call. This differs from Path II's standing introspection call, which passes `false`.( *see the Path I/II Divergence Rule below for why the same function takes different arguments in each context*.)

### [Deprecated]**Step 3 - Human Review**
***This step is now obsolete since we are taking the existing table as is. Behemoth will not perform any type guessing. Type resolving should be done only by the database driver. The user can edit the generated migration.*** 

This is a mandatory stage with no bypass, `[Convention, important]`, split into two calls mirroring the ordinary Resolution stage's shape:

- **`BuildBaselineIssues(report)`** - the Issue Organizer half. Walks the `IntrospectionReport` and produces `(provisional map[string]TableSchema, issues []BaselineIssue, error)`. Unlike the ordinary Planning stage, this only concerns itself with **type reverse-mapping ambiguity** — a baseline has no "missing declared column" or "extra column" divergence to resolve, because there is no prior canonical record yet to diverge from. Those divergences are deliberately deferred to Step 5's first ordinary `generate` call, run immediately after baseline completes.
- `ResolveBaselineIssues(ctx, provisional, issues, presenter, interactive)` — drives every `BaselineIssue` to a decided canonical `Column`, using the same `ResolutionPresenter` interface (and therefore the same `FilePresenter` draft file) as ordinary Resolution. Output is `*ResolvedBaseline` — a type that, like `ResolvedOperationSet`, cannot represent an unresolved decision.
- **Non-interactive/CI baselining is refused entirely.** `[Convention, important]` No default answer exists for a guessed type — a wrong baseline poisons every migration generated on top of it, so unlike Path II's ordinary Resolution (which merely fails closed on unresolved issues), baseline additionally refuses to even _attempt_ a non-interactive run when any ambiguity exists.

`[Limitation, important]` `ResolveBaselineIssues` currently reuses `ResolutionPresenter`/`FilePresenter` by wrapping each `BaselineIssue` into a `PlanIssue` shell purely to reuse the existing draft wire format (label list + chosen index). `PlanIssue.Options[].Operations` is left empty in this path and is never read — the presenter only ever serializes `Label` strings and reads back a selected index, so this works today, but it is a **borrowed shape, not a shared type**. If the draft file format is ever extended to carry richer per-option data (e.g. supporting the deferred "override with a specified type" option below), this adapter will need to be revisited — it currently has no way to carry a `BaselineFieldOption`'s eventual free-text override through the same channel.

`[Deferred]` "Override with a specified type" is documented as a desired option for a type-ambiguity `BaselineIssue` but is not implemented — the current option-index-only draft format has no field for free-text input. Only "Accept guessed type" is currently offered as a real choice.

### **Step 4 - Recording**

`BuildBaselineMigration(resolved *ResolvedBaseline) Migration` constructs one `Migration{ID: "0000_baseline", IsBaseline: true}` whose `Up` comprehensively reflects the resolved state: one `OpCreateTable` per table, plus separate `OpAddIndex`/`OpAddForeignKey` operations for every index and foreign key on that table.

`[Convention]` `OpCreateTable.NewTable.ForeignKeys` is always empty here to prevent table-foreign-key cycles.

Before the migration is applied, the user can review and edit the file. Then `deps.Runner.Apply(ctx, []Migration{baselineMigration})` is called with this single migration. Because `IsBaseline` is `true`, the Runner's `applyOne` routes it to `driver.RecordBaseline` instead of `driver.ApplyMigration` — see Execution Semantics below for exactly what this means and does not mean.


## **Step 5 - Ordinary Flow Takeover**

`[Convention, important]` Regardless of whether the Baseline Phase ran, `RunMigration`'s final action is always a direct call to `RunGenerate(ctx, cfg, current, deps.GenerateDeps, interactive)`. This applies both to greenfield and brownfield cases. Any divergence between what baseline recorded and what `current` actually declares surfaces here, through the ordinary Planning/Resolution machinery, as the first real generated migration.

## **Execution Semantics - `ApplyMigration` vs. `RecordBaseline`**

`[Convention, important]` This is the mechanism that makes "replay produces accurate state" true without literally re-executing history:

- **`ApplyMigration`** (every ordinary migration): executes every operation in `Up` as real DDL against the live database, atomically with the ledger insert and snapshot upsert, per the driver's own `AtomicityLevel`.
- **`RecordBaseline`** (the `0000_baseline` migration only): writes the ledger row and the snapshot upsert with the **exact same atomicity contract**, but executes **zero** schema-modifying statements. The tables already exist live; issuing `CREATE TABLE` against them would simply fail.
- **What "replay" actually means, precisely stated:** nothing re-runs `0000_baseline`'s DDL. What is reproduced accurately is the **in-memory snapshot projection** — `applyOperationsToSnapshot` computes the resulting canonical state from a migration's `Up` operations identically whether that migration was really executed or only recorded. The distinction between "did DDL happen" and "is the snapshot accurate" is what allows baseline to seed history without rewriting it.

## Path I / II Divergence Rule - `trackExtraColumns`

`[Convention, important]` `RunIntrospection` is shared code between both Paths and both a standing (Path II, every `generate`) and one-time (Path I, baseline only) use, but its `trackExtraColumns` argument differs by caller:

- **Path I baseline** → `true`. Path I owns a durable canonical snapshot; a column that exists live but was never part of any behemoth declaration is unambiguous — it's real data the tool must account for, so it belongs in the baseline recording.
- **Path II standing diff** → `false`. Path II has no prior canonical record on a first run to distinguish "behemoth's own column that isn't declared anymore" from "the developer's own unrelated custom field" — per the earlier documented `[Deferred]` gap, an unmatched extra live column is silently omitted rather than risk a wrong drop candidate.

## `MigrationDeps`- dependency shape

```go
type MigrationDeps struct {
	Introspector SchemaIntrospector
	Runner       MigrationRunner
	GenerateDeps GenerateDeps       // reused verbatim from RunGenerate — Presenter, Generator live here
	Presenter    ResolutionPresenter // same underlying instance as GenerateDeps.Presenter — one draft file per run, not two
}
```

`[Convention]` `Presenter` is duplicated as a field only to make the Baseline Phase's dependency explicit without reaching into `GenerateDeps` — it must always be the same concrete instance, and not a second, independently-configured presenter, or Steps 3 and 5 would write to two different draft files in one run.

## Helper - `snapshotAsRegistry`

`[Implementation Detail]` Adapts a persisted `SchemaSnapshot` into the read-only `SchemaRegistry` shape `FromSnapshotDiff` expects as "previous." `Declare`/`ExtendColumn`/`ExtendIndex` are unreachable on this adapter — it exists purely to carry values for a diff, never to accept new registrations, and returns an `Internal`-classified error if called, since that should never happen given how it's constructed.


# **Execution Flow** 

## **Path Managed - I**

1. Run Command
2. `RunMigration` - Check run state, whether run is called for the first time or not. This check is performed by checking existence of the Ledger table. 
	1. **First Time Run**
		1. Empty Migration Folder - Run `PartitionForBaseline` to check if there are baseline candidates. If there are, proceed with baseline migration, otherwise, i.e. if no tables exist, proceed to `RunGenerate` from scratch
		2. Folder has a single baseline migration file - If a single baseline migration is found in the folder, it means a first run has been made and was awaiting a confirmation. For maximum correctness, a baseline migration is generated afresh and compared with the user confirmed file. This will catch live state modifications in-between the two runs. If the state has changed, a new migration is regenerated and written, waiting for confirmation. Otherwise, the baseline migration is applied.
	2. Not a First Time Run - The normal generate route continues (Check pending -> Apply Pending if any(with confirmation)  -> `RunGenerate` - {Plan -> Resolve -> Generate})
			

# **Custom Migrations**

A `CustomMigration` is a hand-authored, named group of operations that rides along with the generated ones: it is ordered among them in the dependency graph, frozen into the same `Migration`, and applied (Path I) or handed off (Path II) exactly like generated operations. It exists for steps the differ cannot derive from comparing declared and live shapes.

```go
type CustomMigration struct {
	Name      string            // permanent identity, see Emitted Once below
	Up        []SchemaOperation
	Down      []SchemaOperation // optional; nil makes the whole migration irreversible
	DependsOn []string          // generated operation IDs, or other custom migrations by Name
}
```

`[Convention, important]` **Emitted exactly once.** A custom migration is frozen into one generated `Migration` and is history from then on. The `Name` is the only thing that tracks this, so names are permanent.

### **Stage 0 - Declaration**

- The application declares custom migrations in `PrepareConfig.Migrations`. `Prepare` carries them on `PreparedApp.Custom`, and `PreparedApp.Declared()` pairs them with the frozen schema registry into `core.Declared{Schemas, Custom}`, the single input every migration entry point takes (`RunGenerateCLI`, `RunGenerate`, `RunMigration`).
- `Prepare` validates them up front, before plugin ordering, via `ValidateCustomMigrations`. Each rule fails `Prepare` with a configuration error:
	- every custom migration has a non-empty `Name`, and names are unique
	- every operation, in `Up` and `Down`, has a non-empty `ID`
	- no operation ID is used by two different custom migrations
	- no operation ID equals a custom migration `Name` (both are node identities in the Generation stage graph)
- These are the checks that need no plan. Collisions with *generated* operation IDs depend on the plan and are checked at Generation.
- `[Deferred]` **Plugin-declared custom migrations.** `PluginInitContext` lives in `types`, which cannot reference `migration/core` types without an import cycle. Supporting plugins means moving `SchemaOperation` and `CustomMigration` into `types/schema`, which is deferred until a plugin needs it.

### **Stage 1 - Introspection / Diff**

- Custom migrations take no part. Introspection compares `Declared.Schemas` against the live database (Path II) or the snapshot (Path I) only.
- **Baseline phase (Path I, brownfield):** the baseline records live state only and never includes custom migrations. Pending custom migrations go into the first ordinary migration generated after the baseline is recorded.

### **Stage 2 - Planning**

- `buildMigrationPlan` runs `BuildPlan` on the schemas as usual, then sets `MigrationPlan.Custom` to the *pending* custom migrations (`pendingCustomMigrations`):
	1. Read every migration file in `FolderPath` (`ReadDiskMigrations`).
	2. Collect the names listed in each file's `Migration.Custom`.
	3. Keep only the declared custom migrations whose `Name` is not among them, in declaration order.
- Custom migrations never produce `PlanIssue`s and are never tiered. The planner did not derive them from a divergence, so there is nothing for it to propose options for.
- `[Convention]` A plan with no generated operations but at least one pending custom migration is still a migration. Generation proceeds and does not report "nothing to generate".

### **Stage 3 - Resolution**

- Pass-through. `ResolveIssues` copies `MigrationPlan.Custom` into `ResolvedOperationSet.Custom` untouched.
- Custom migrations never appear in the draft file and need no developer decision: declaring one is the decision. The fail-closed gate on unresolved issues applies to generated operations only.

### **Stage 4 - Generation**

Checks, before the graph is built (both abort generation):

- **Inline foreign keys:** `checkNoInlineForeignKeys` covers each custom migration's `Up`. An `OpCreateTable` carrying `ForeignKeys` is rejected, and the foreign key must be authored as its own `OpAddForeignKey`, same as the planner's output.
- **Collisions with generated operations:** `checkCustomCollisions` rejects a custom migration whose `Name`, or any `Up`/`Down` operation ID, equals a generated operation ID in this plan. Once frozen, `Up` and `Down` are flat lists, and `Down` construction, rendering and the runner all key on operation IDs, so two operations with one ID cannot coexist in a migration.

Dependency graph:

- Each custom migration is **one node**, keyed by its `Name`, not one node per operation. Its operations are never interleaved with anything else.
- **Rule 1 applies:** the node depends on `OpCreateTable` of every table its `Up` operations target, when that table is created in the same plan.
- **Rules 2 and 3 do not apply.** They are evaluated for generated foreign-key operations only. A custom migration that needs a referenced table created first must say so through `DependsOn`.
- **Rule 5 - explicit edges:** each `DependsOn` entry becomes an edge. An entry may name a generated operation ID or another custom migration's `Name`.
- `[Convention]` A `DependsOn` entry naming something not in this plan is dropped silently, on the same assumption as every other edge: the target was applied in an earlier migration. The consequence is that a typo, or a reference to an operation *inside* another custom migration (those IDs are not graph nodes), is also dropped silently rather than reported.
- Cycles through `DependsOn` are authoring errors, reported with `KahnSort`'s cycle path (see Mutual Table Reference above).

Freezing:

- **`Up`:** walking the sorted nodes, a custom node contributes its `Up` operations as one contiguous block, in authored order.
- **`Down`:** walking the sorted nodes in reverse, a custom node contributes its authored `Down` as written. It is **not** inverted or reversed, so it must already be in execution order. A custom migration with a non-empty `Up` and no `Down` makes the **entire** migration's `Down` nil, per the all-or-nothing rule in Reverse Operation Construction.
- **`Migration.Custom`:** the names of every custom migration frozen into this migration, sorted so that a regenerated migration compares equal to the one on disk. The field is omitted from the JSON when empty, so migrations without custom migrations keep their existing file shape.

### **Stage 5 - Write and Render**

- The migration file carries `"Custom": [...]`. This field is the only durable record that a custom migration was emitted, and the next Planning stage reads it back.
- Custom operations are `SchemaOperation`s, so the driver's `MigrationRenderer` renders them into the `.sql` script with no special handling.

### **Stage 6 - Apply**

- **Path I:** the runner applies the migration's `Up` as a unit through `ApplyMigration`. Custom operations run in the same transaction as the generated ones, where the driver's atomicity level allows. `applyOperationsToSnapshot` folds every `Up` operation, custom ones included, into the next `SchemaSnapshot`, so the snapshot reflects custom changes for the next diff.
- **Path II:** behemoth stops at the written files, and the developer's migration tool runs the script.

### **After Emission - Identity Rules**

- Editing an emitted custom migration in code has no effect. The frozen file is what applies.
- Deleting an emitted custom migration from code is harmless. It is already history.
- `[Convention, important]` **Renaming** an emitted custom migration makes it a new one, and it **is emitted again** under the new name. **Reusing** an emitted name for a different migration means the new one is **never emitted**. Neither case is detectable, because the name is the identity.
- `[Convention]` **Path II limitation**, the same one as `LatestMigrationID`: when the developer moves a generated file out of `FolderPath`, its `Migration.Custom` record goes with it, and every custom migration it contained is emitted again on the next run. As with migration IDs, behemoth owns no record beyond the staging folder.

### **Known Limitations**

- `[Important]` **No safe schema-only use yet.** The differ converges on the declared schema regardless of custom migrations, so with only schema operations available:
	- a custom operation that **overlaps** the declared schema (e.g. adds a column the registry also declares) is generated by the differ as well, because the diff runs before the custom migration is applied, so the change is applied twice. Both paths. If the custom operation happens to reuse the generated operation's ID, the collision check rejects the migration instead;
	- a custom operation that goes **beyond** the declared schema (e.g. an index the registry doesn't declare) is planned for removal on the next run **in Path I**: the snapshot diff tracks extras, so an extra index or foreign key is dropped and an extra column is raised as a drop issue. **Path II** ignores live extras (`trackExtraColumns = false`), so there it survives, but only by that rule, not by design.

	`[Convention]` A custom migration must end at the declared schema, not elsewhere. Its legitimate uses are steps the differ cannot infer, ordered relative to generated operations, and those are mostly data steps.
- `[Deferred]` **Data operations.** `SchemaOperation` has only structural kinds, so the backfill use case named above is not expressible yet. The intended shape is an `OpExec` kind carrying per-driver SQL and an optional `Down`. Drivers execute and render it like any other operation, and it leaves the snapshot untouched.
- `[Deferred]` **Plugin-declared custom migrations**, see Stage 0.
- `[Note]` The Planning stage's "Developer-Authored Custom Operations" branch describes custom operations carrying their own tier declaration. `CustomMigration` has no tier field, and custom migrations bypass tiering and Resolution entirely, as described above.
