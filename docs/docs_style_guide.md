# Behemoth documentation style guide

These instructions apply whenever you write or edit documentation for Behemoth. They are written for both human contributors and AI agents. The base style is the [Google developer documentation style guide](https://developers.google.com/style). Where this file and the Google guide disagree, this file wins. Where this file is silent, follow the Google guide.

Sentences marked [For Agents] apply only to AI agents. Human contributors can skip them. Everything else applies to everyone.

## 1. Identify the doc type first

Before writing, decide which of the three types you are producing. Each has different rules.

| Type | Where it lives | Primary reader |
|---|---|---|
| **API docs** | Go doc comments (`//` above exported identifiers), `doc.go`, and `example_test.go` | A developer who imports Behemoth |
| **Website docs** | Compiled from API docs plus guide pages | A developer evaluating or learning Behemoth |
| **Internal docs** | `docs/internal/`, ADRs, design notes, unexported-code comments, `CONTRIBUTING.md` | A Behemoth maintainer or contributor |

The type determines what you may say, so don't guess. 

**[For Agents]** If a request is ambiguous, ask which type it is. Don't guess, because the type determines what you may say.

**Source-of-truth rule:** Website docs are compiled from API docs. Never write content directly into a website page that duplicates or contradicts a doc comment. Fix the doc comment, then regenerate. Guide pages (tutorials, concepts, how-tos) are the only content authored directly for the website.

## 2. Rules that apply to every doc type

These come from the Google guide and are non-negotiable.

- **Second person.** Address the reader as "you." Don't use "we" to mean the maintainers ("we recommend" becomes "use" or "Behemoth recommends").
- **Active voice, present tense.** Write "The runner applies the migration," not "The migration will be applied." Avoid future tense except for genuinely future events.
- **Imperative for instructions.** "Call `Freeze` after all plugins register."
- **Sentence-case headings.** "Configure the migration path," not "Configure The Migration Path."
- **Task headings start with a verb** ("Generate a migration"). Concept headings are noun phrases ("Migration paths"). Reference headings are names ("MigrationConfig").
- **Serial (Oxford) comma.**
- **Descriptive link text.** Write "see [Migration paths](...)," never "click here" or a bare URL.
- **Code font** for identifiers, file names, flags, config keys, type names, and literal values. Use fenced code blocks with a language tag for multi-line code.
- **No filler or minimizing words:** "simply," "just," "easy," "obviously," "of course," "please," "note that" (unless it introduces a real note).
- **No Latin abbreviations:** use "for example" not "e.g.," "that is" not "i.e.," "and so on" not "etc."
- **No humor, idioms, or culture-specific references.** Readers are global and many use translation tools.
- `[For Agents]` **Keep emphasis plain.** Don't stress a word with capital letters, and don't write "MUST", "ALWAYS", or "NEVER" in capitals. Rephrase the sentence so the requirement is clear from its wording. Use "must" and "never" only for real contractual requirements.
- `[For Agents]` **Don't force groups of three.** Don't pad a list, a run of adjectives, or a set of examples to three items because three sounds complete. Use as many as the content has.
- `[For Agents]` **Use plain punctuation.** Limit em dashes. Prefer a comma, a colon, parentheses, or a new sentence. Write an ellipsis as three ASCII periods (`...`), not the single character `…`. Use the inline syntax that is normal for the format, such as backticks for identifiers in Markdown.
- **Inclusive language.** Use "allowlist/denylist," "primary/replica," and gender-neutral wording.
- **One idea per sentence.** Prefer sentences under about 25 words.
- **Lists:** Use numbered lists for ordered steps and bullets for unordered items. Make list items parallel. Introduce every list with a sentence ending in a colon.
- **Placeholders in code** use `UPPER_SNAKE_CASE` and are explained immediately after the snippet.
- **Every code example must compile.** Prefer a runnable `Example*` test function over an inline snippet.
- **Terminology consistency.** Use one term for one concept everywhere. See the glossary in section 6.

## 3. Key distinctions between the three types

### 3.1 Audience assumptions

| | API docs | Website docs | Internal docs |
|---|---|---|---|
| **Who** | Go developer integrating Behemoth into an application | Developers at varying levels, including those who haven't chosen Behemoth yet | Maintainers and contributors who work inside the repository |
| **Assumed knowledge** | Fluent in Go (interfaces, contexts, errors). Knows basic authentication concepts. Does **not** know Behemoth's internals or history. | Knows what authentication is. May be new to Go, to plugin systems, or to schema migrations. | Knows Go well and has read the architecture overview. Understands the plugin lifecycle and migration engine. |
| **Don't assume** | That the reader has read other pages, the source, or the design history | That the reader has read the API reference | That a new contributor knows past design discussions. Link to the decision record instead. |
| **Depth** | Precise and complete for the one symbol described | Layered: quick start first, then concepts, then links to reference | As deep as needed, including trade-offs and rejected alternatives |

### 3.2 Voice and tone

| | API docs | Website docs | Internal docs |
|---|---|---|---|
| **Tone** | Neutral, terse, exact | Friendly, professional, encouraging, but still plain | Direct, candid, engineering-focused |
| **Person** | Avoid addressing the reader where possible. Describe what the symbol does. Use "you" only in guidance sentences. | "You" throughout | "You" for instructions. "Behemoth" or the component name for behavior. |
| **Sentence form** | Third-person verb opens the description ("Returns...," "Registers...," "Reports whether...") | Imperative for steps, present tense for explanation | Imperative for procedures, declarative for rationale |
| **Opinions and rationale** | Only what affects correct use (constraints, side effects, concurrency, errors) | Light guidance on when to choose an option | Full rationale, trade-offs, and "why not X" are welcome |
| **Warnings** | State the consequence precisely ("Calling `Declare` after `Freeze` returns a configuration error.") | Use a labeled note or warning callout | Be blunt about risks and invariants |

### 3.3 Allowed terms and references

This is the biggest difference. API and website docs are public and must stand alone.

| Content | API docs | Website docs | Internal docs |
|---|---|---|---|
| Exported identifiers (`MigrationConfig`, `PathManaged`, `Model`) | Yes | Yes | Yes |
| Unexported identifiers (`runOngoing`, `snapshotRegistry`, `buildDependencyGraph`) | **No** | **No** | Yes |
| Internal repository names, private module paths, internal service names | **No** | **No** | Yes |
| Project code names, working titles, roadmap names | **No** | **No** | Yes |
| References to design conversations, planning "rounds," "steps," "manifesto," "Path I/II," "earlier correction," or "as discussed" | **No** | **No** | Only if you link to the written decision record |
| Algorithm names (for example, Kahn's algorithm) | Only if the reader needs it to use the API correctly | Only in concept pages that explain behavior | Yes |
| Names of maintainers or authors | **No** | **No** | Only via git history or `CODEOWNERS`, not in prose |
| Unreleased or deferred features (`[Deferred]`, "intent: add later") | **No** | **No** | Yes, clearly labeled with status |
| Third-party tools (goose, golang-migrate, Atlas) | Only when integration is a documented, supported feature | Yes, in integration guides | Yes |
| TODOs and unresolved questions | **No** | **No** | Yes, with an issue link |

**Rule of thumb:** If a reader outside the Behemoth team would have to ask "what is that?", the term doesn't belong in API or website docs.

### 3.4 Structure and format

**API docs (Go doc comments)**

- Follow Go conventions on top of the Google guide: the comment begins with the identifier name, and the first sentence is a complete summary ("`Driver` executes schema operations against a database.").
- Document every exported type, function, method, constant, and variable.
- For methods and functions, cover as needed, in this order: what it does, parameters that need explanation, return values, errors returned (name the error codes or types), side effects, concurrency safety, and lifecycle constraints (for example, "must be called before `Freeze`").
- For interfaces, state the contract an implementer must satisfy, including what the caller guarantees and what the implementation must guarantee.
- For enumerated constants, document each value on its own line.
- Don't describe how the code works internally. Describe observable behavior.
- Don't include rationale, history, or alternatives you considered.
- Add an `Example*` function for any non-trivial symbol.
- Use Go doc link syntax (`[MigrationConfig]`) for cross-references.

**Website docs**

- Organize by reader goal: Get started, Concepts, How-to guides, Reference (generated).
- Each page has one purpose. Don't mix a tutorial with a concept explanation.
- Start every page with one or two sentences saying what the page covers and who it's for.
- Tutorials and how-tos: state prerequisites, then numbered steps, then expected result.
- Concept pages: explain the "what" and "why" in terms of the reader's goals, not implementation.
- Include a complete, copy-pasteable example per guide.
- Link to the generated API reference rather than repeating signatures.
- Never edit generated reference pages by hand.

**Internal docs**

- Architecture and design docs: context, goals, non-goals, design, alternatives considered, consequences.
- Decision records (ADRs): record every significant design decision as an Architecture Decision Record in `docs/internal/decisions/`. Each record states the problem, the options considered with their trade-offs, the chosen option and why, and when to reconsider. Never rewrite an accepted decision. Add a new record that supersedes it. Follow the conventions and template in `docs/internal/decisions/README.md`.
- Link code to the decision that shaped it with a `// See ADR-NNNN.` comment, as described in the decisions README. Use these references in internal docs and comments on unexported code only, never in API or website docs.
- `[For Agents]` Draft ADRs with status `Proposed` when asked. Never set a status to `Accepted`, and never edit or supersede an accepted record unless the user explicitly asks. The maintainers own decisions.
- Document invariants explicitly (for example, migration safety rules, plugin lifecycle ordering, transaction nesting). State what breaks if the invariant is violated.
- Comments on unexported code explain **why**, not what. Don't narrate the code.
- Mark deferred work as `Deferred:` or `TODO(issue-link):` with a clear description.
- Date-stamp or version-stamp anything likely to go stale.

### 3.5 Maturity and uncertainty

| | API docs | Website docs | Internal docs |
|---|---|---|---|
| Unfinished or partial behavior | Use `Deprecated:` or `Experimental:` markers with a precise statement. Don't document stubs as if they work. | Omit, or label the page "Experimental" | Describe openly, including known gaps |
| Known bugs or limits | Document as a limitation only if users can hit it | Mention in a "Limitations" section | Track in issues and link |

## 4. Pre-publish checklist

Run through this before you finish any doc change.

1. Did I identify the doc type and follow its column in section 3?
2. Do API and website docs contain **no** unexported names, internal repository names, code names, or references to design discussions?
3. Is every sentence in active voice and present tense, in second person where addressed to the reader?
4. Does each exported symbol's doc comment start with its name and a complete summary sentence?
5. Do all code examples compile, and are placeholders explained?
6. Are headings in sentence case, and do task headings start with a verb?
7. Are all links descriptive and valid?
8. Did I use the glossary terms consistently?
9. Did I change a generated website page by hand? If yes, revert and fix the source comment instead.

## 5. When requirements conflict

- Accuracy beats style. Never soften a precise statement to match a tone rule.
- Public docs beat internal convenience. If a fact is needed publicly, restate it in public terms and don't link to an internal doc.
- If you can't describe a symbol's behavior without referencing internals, flag it to the maintainer as an API design smell instead of leaking internals into the docs.

## 6. Glossary (keep this list current)

Use these terms consistently. Add new entries as the vocabulary is settled.

| Preferred term | Avoid | Notes |
|---|---|---|
| migration | change script, patch | A frozen, ordered set of schema operations |
| schema operation | DDL step, action | One create, alter, or drop instruction |
| migration path | mode, flow | `PathManaged` or `PathGenerateOnly` |
| plugin | extension, module | |
| model | entity, struct (in prose) | A type that implements `Model` |
| registry | catalog | Use "schema registry" on first mention |

Add the project's confirmed public terms here. Move any term that is still internal-only to the internal glossary in `docs/internal/`.