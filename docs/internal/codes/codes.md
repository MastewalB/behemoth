# One-time codes

This document explains the code manager (`types.CodeManager`, `transport.DefaultCodeManager`): what a code is next to a token, how it is stored, and how its three operations stay correct under concurrent calls.

The code it refers to lives in:

- `types/codes.go`: `CodeManager`, `CodeOptions`
- `transport/codes.go`: `DefaultCodeManager`
- `models/verification_code.go`: the model and the table
- `store/verification_codes.go`: the store operations
- `errors/code.go`: the one rejection

## A code next to a token

| | Token | Code |
| --- | --- | --- |
| Secret | a long random string | 4 to 12 digits |
| Travels | in a link | typed by a person |
| Found by | the hash of the secret (`lookup_hash`) | kind and subject |
| Guessing | not feasible | bounded by an attempt count |
| Live at once | any number per subject | one per kind and subject |
| After use | marked consumed | deleted |
| Table | `tokens` | `verification_codes` |

A six-digit code can't be found by its own hash: two users can hold the same code, and whoever looked one up by hash could try all million. So a code is found by who it is for, and each look costs an attempt.

## The table

| Column | |
| --- | --- |
| `id` | primary key |
| `kind`, `subject` | unique together |
| `code_hash`, `key_version` | `Crypto.Secrets.Hash` of kind, subject and code |
| `attempts_left` | counts down from `CodeOptions.MaxAttempts` |
| `metadata` | JSON, for the issuing flow |
| `expires_at`, `created_at` | |

- **The hash covers the kind and the subject.** A hash copied onto another row matches nothing there.
- **The hash is keyed** (the HMAC tokens use), so a copy of the table does not allow trying a million codes offline.
- **`attempts_left` counts down.** `Consume` then needs no definition of the kind to know the limit, which is why there is no catalog of code kinds.

## The operations

**`Issue`** generates the digits (`digits`: random bytes, dropping those of 250 and above so each digit is uniform), hashes, and calls `Store.ReplaceVerificationCode`, which deletes the row for the kind and subject and creates the new one. Two calls racing can collide on the unique index; the loser deletes and creates again.

**`Consume`** runs in this order:

| Step | What | Refusal |
| --- | --- | --- |
| 1 | `Store.SpendVerificationCodeAttempt`: read the row, then `UpdateOne` guarded on the id and the count that was read | no row, or `attempts_left` is 0 |
| 2 | compare `expires_at` with the store's clock | expired |
| 3 | `Secrets.Verify` | wrong code |
| 4 | `Store.DeleteVerificationCode` | already deleted by a concurrent call |

- **The attempt is taken before the comparison.** If it were taken after a wrong guess only, guesses arriving together would each read the same count, compare, and share one attempt.
- **The guarded update is the same technique as the rate-limit counter** (`IncrementRateLimit`): `UpdateOne` re-checks its expression in the write, so of several calls that read the same count one writes and the others read again.
- **The delete is the at-most-once step.** `DeleteOne` returns NotFound when the row is gone, so of two calls with the right code one succeeds.
- **Every refusal is one error**, `code_invalid`, with the reason in its internal message only.
- **A right guess costs an attempt too**, which does not matter since the row is then deleted.

**`Revoke`** deletes the row for a kind and subject.

`Store.DeleteUser` deletes the rows whose subject is the user's id, in the transaction that deletes the user. `Store.PurgeExpiredVerificationCodes` does one pass over expired rows; nothing schedules it.

## What is left out

- **No hook points and no audit events.** The token manager fires `token.*`. A code is always consumed inside a flow that has failed and after points of its own, and those carry the reason.
- **No key-value backend.** Codes are rows.
- **No lockout beyond the code.** After the last attempt the subject asks for a new code, and the issuing flow's rate limit bounds how often.

## Tests

`TestCodeManager` (`tests/plugins/phonenumber_test.go`) covers the manager through a booted application, and `verificationCodesContract` (`tests/store/contract_test.go`) the store operations on every adapter.

## Design decisions

### A table of its own, not the user row or the tokens table
**Context:** A one-time code needs a place to live between being sent and being typed.
**Options considered:**
- *Columns on `users`.* No new table. A code often exists for something that is not on the user yet (a number being added), a user can have several at once, and each needs its own attempts and expiry.
- *Rows of `tokens`.* The table has a kind, a subject, a hash, metadata and an expiry already. A token is found by `lookup_hash`, which is unique per kind and required; a code has no such value. It would also need an attempts column that means nothing for a token, and "one per subject" contradicts how tokens are used.
- *A table of its own.* One more core table. Each column has one meaning.

**Decision:** The third.
**Revisit if:** a third kind of short-lived secret appears and the three tables turn out to share most of their columns.

### In core, not in the phone number plugin
**Context:** The phone number plugin is the only consumer today.
**Options considered:**
- *A table and a manager inside the plugin.* Core stays smaller. A second-factor plugin by SMS and a code by email would each write the attempt counting again, or depend on the phone plugin for it.
- *A core component.* Available to every plugin through `AuthContext.Codes`. Every application gets the table, used or not.

**Decision:** The second. The concurrency rules above are the kind of thing that should exist once.

### Deleting a used code, not marking it
**Context:** A token keeps its row after use, with `consumed_at`.
**Options considered:**
- *Mark it consumed.* A record stays. "One live code per kind and subject" then needs the unique index to ignore consumed rows, which is a partial index and differs per database.
- *Delete it.* A plain unique index is enough, and the delete is itself the at-most-once step.

**Decision:** Delete. The record of what happened is the audit event of the flow that consumed the code.
