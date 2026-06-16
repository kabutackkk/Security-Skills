# Invariants, Inputs, Arithmetic, Time, and Exceptions

This reference expands checkpoints `0x000f` through `0x0014`.

## Contents

- `0x000f` Template and choice invariants
- `0x0010` Input and argument validation
- `0x0011` Arithmetic, rounding, and units
- `0x0012` Time-based rights and expiry
- `0x0013` Exceptions, rollback, and failure handling
- `0x0014` Nonconsuming and preconsuming choices

---

## 0x000f-template-and-choice-invariants-should-be-enforced-on-ledger

**Description:**
Critical business rules must live in DAML itself, not in UI code, scripts, or operator convention. `ensure` protects create-time invariants and `assert` or equivalent checks protect choice-time transition invariants. This includes positivity, bounded ranges, uniqueness constraints, and safe field-size limits for economically or operationally significant values.

**Identify:**
1. Locate `ensure`, `assert`, `assertMsg`, and related validation logic in templates and choices.
2. Review comments, docs, and off-ledger code for assumptions that do not visibly appear as on-ledger checks.
3. Identify fields such as amounts, prices, quantities, text fields, lists, maps, and identifiers whose safe range or size is assumed by later logic.

**Analyze:**
1. Enumerate the business invariants that must hold for every active contract and every sensitive transition.
2. Verify that those invariants are enforced on-ledger at the exact points where they matter, including create paths, archive-and-recreate paths, and sensitive choices.
3. Check whether a caller can bypass UI checks or operator conventions and create semantically invalid state directly on-ledger.
4. Review coupled invariants that span multiple fields or contracts, such as threshold values that depend on member count. These often hold at one update point but break after later add/remove operations.

**Remediation:**
1. Put critical invariants in DAML, not just in surrounding systems.
2. Re-check invariants on successor contracts and sensitive choices, not just on initial create.
3. Include size and range bounds for fields that can affect economics, privacy, or operability.
4. Where one parameter depends on another, enforce the relation after every change to either side or provide an atomic combined update.

**Related:** `0x0010` (input validation), `0x0015` (successor invariant preservation)

---

## 0x0010-inputs-and-choice-arguments-should-be-validated-against-business-rules

**Description:**
Strong typing in DAML does not eliminate input-validation risk. Choice arguments, template fields, party collections, identifiers, optionals, and amounts can still be semantically invalid and lead to authorization bypass, bad accounting, or broken workflow state.

**Identify:**
1. Review all externally influenced choice arguments and template fields copied from proposals, upstream contracts, API calls, or helper outputs.
2. Locate dynamic `[Party]`, `[Text]`, `Optional`, `Map`, and `Set` inputs, plus quantities, fees, rates, identifiers, and denominator-like parameters.
3. Identify fields duplicated alongside referenced contracts or factory outputs, since duplicated metadata can drift from the source object.

**Analyze:**
1. Determine which inputs influence authorization, amounts, recipients, deadlines, uniqueness, or workflow routing.
2. Verify semantic validation such as non-empty values, allowed ranges, size bounds, uniqueness, party membership, identifier consistency, positive amount handling, and non-zero denominator guards.
3. Check whether malformed but well-typed inputs can redirect value, widen permissions, create unusable contracts, or move the state machine into unintended branches.
4. Treat configuration structure as input too: piecewise schedules, stepped rates, timeout settings, and tier lists often need ordering, monotonicity, and operationally sane lower bounds beyond simple positivity checks.

**Remediation:**
1. Validate every caller-controlled input against business semantics, not just type correctness.
2. Cross-check duplicated metadata against referenced contracts or helper outputs before binding state.
3. Audit dynamic lists and maps for duplicates, empties, and out-of-domain values.
4. Validate ordering and monotonicity for stepped or piecewise configuration, and reject values that are syntactically valid but operationally impossible.

**Related:** `0x000f` (on-ledger invariants), `0x0011` (arithmetic safety)

---

## 0x0011-arithmetic-rounding-and-unit-conversions-should-preserve-economic-intent

**Description:**
Authorization can be correct while economics are still wrong. DAML applications that compute balances, fees, allocations, partial fills, splits, or settlements can lose value through rounding drift, sign confusion, unit mismatch, or denominator mistakes, especially when governance-controlled parameters flow into formulas.

**Identify:**
1. Locate every amount calculation, fee or rate calculation, split, conversion, percentage, cap, and partial settlement path.
2. Review arithmetic that spans multiple templates or multiple transfer paths intended to preserve the same business result.
3. Identify governance- or admin-controlled parameters that are used in multiplication, division, or cap logic.

**Analyze:**
1. Verify conservation across each path: total debits, credits, fees, and change should reconcile to the intended total.
2. Check unit consistency, rounding policy, minimum-unit behavior, and denominator safety, including zero and misconfiguration cases.
3. Compare sibling paths that implement the same business effect to ensure they do not silently diverge in arithmetic behavior.
4. Add defensive reasoning around intermediate values: negative interval widths, negative fees, or estimated lock durations based on stale timestamps can silently inflate, undercharge, or block later settlement.

**Remediation:**
1. Enforce explicit rounding and unit-conversion rules.
2. Guard zero, negative, and denominator-sensitive cases even when config is assumed "sane."
3. Test edge amounts and repeated execution to detect drift.
4. Assert non-negative intermediate values in fee and tier calculations, and check that "estimated" time-based charges use the actual lock or holding duration being created.

**Related:** `0x0010` (input validation), `0x0019` (batch settlement balance)

---

## 0x0012-time-based-rights-and-expiry-should-be-enforced-at-choice-time

**Description:**
Deadlines, settlement windows, cooldowns, and expiries are easy to model incorrectly. If time is checked only when a proposal is created, stale rights remain exercisable later. On Canton, ledger time also has fuzziness and cross-synchronizer flows must not assume a single global event order.

**Identify:**
1. Locate `getTime`, expiry fields, maturity dates, accept windows, grace periods, and time-sensitive permissions.
2. Review create-time checks, exercise-time checks, renewal paths, cancellation paths, and expiration choices.
3. Identify workflows that span synchronizers, migrations, or reassignment boundaries where ordering assumptions may weaken.

**Analyze:**
1. Determine which rights, choices, or transitions are valid only inside a specific time window.
2. Verify that ledger time is checked inside the exact choice that consumes the right, claim, invitation, or permission.
3. Review boundary semantics, temporal consistency between related fields, and assumptions about wall-clock precision or global event order.
4. In confirmation and governance flows, ensure expired confirmations are filtered at execution time and that stale confirmations do not permanently block fresh ones from being submitted.

**Remediation:**
1. Re-evaluate time bounds at the exact exercise that consumes the right.
2. Explicitly encode temporal relations between fields rather than inferring them from creation order.
3. Audit near-boundary behavior and cross-synchronizer assumptions separately from ordinary expiry logic.
4. Add operationally sane lower bounds to configurable timeouts when a tiny but non-zero value would make the workflow unexecutable in practice.

**Related:** `0x0006` (lock/mandate expiry), `0x0018` (stale pending state)

---

## 0x0013-exception-handling-and-rollback-should-not-mask-security-failures

**Description:**
Caught DAML exceptions create rollback behavior. This is useful, but dangerous when workflows assume a risky step happened even though it rolled back, or when contracts are archived before code that can still fail.

Version applicability note:
User-defined DAML exceptions and `try`/`catch` support are legacy and may be deprecated or absent in newer stacks. If the target project version does not use catchable exceptions, mark the exception-specific parts of this checkpoint `Not Applicable`, but still review rollback assumptions around `abort`, `error`, helper fallbacks, and failure handling in surrounding orchestration.

**Identify:**
1. Locate `try`, `catch`, `throw`, `abort`, `error`, and helper patterns that downgrade failures into alternative flows.
2. Review create, fetch, exercise, settlement, and archival logic wrapped in exception handling.
3. Find code that archives, reserves, or otherwise changes durable state before a downstream operation that may still fail.

**Analyze:**
1. Determine which effects are rolled back when an exception is thrown and caught.
2. Verify that fallback paths re-establish the exact invariants expected after failure rather than proceeding under a false assumption about what succeeded.
3. Check whether authorization or invariant failures are being caught and converted into success-looking outcomes or ambiguous states.
4. The exploit path is: a risky operation wrapped in `try`/`catch` fails, the fallback path proceeds under wrong assumptions about what rolled back, or a contract already archived is permanently lost.

**Remediation:**
1. Treat security checks and core invariants as terminal failures, not recoverable convenience branches.
2. Avoid archiving or consuming critical contracts before downstream actions are known to be safe.
3. Make rollback assumptions explicit and test them.

**Related:** `0x0015` (archive-and-recreate invariants), `0x0016` (stuck states)

---

## 0x0014-nonconsuming-and-preconsuming-choices-should-match-economic-intent

**Description:**
Choice consumption mode is a security property. `nonconsuming` choices can be replayed on the same active contract, while `preconsuming` choices archive before the body runs. Using the wrong mode can make one-shot rights replayable or can create liveness failures because the contract disappears too early.

**Identify:**
1. Locate every `nonconsuming` and `preconsuming` choice, especially on approvals, claims, withdrawals, cancellations, matches, and settlements.
2. Identify business actions that are meant to be one-time, replay-resistant, or reserving.
3. Review how those choices interact with retries, off-ledger automation, and downstream failure behavior.

**Analyze:**
1. Determine whether the right exercised by the choice should be reusable, single-use, or reserved before downstream work begins.
2. Verify that the selected consumption mode matches that business intent and that repeated invocation or early archival is safe.
3. Check whether replay, duplicate settlement, duplicate approval, or blocked recovery can occur purely because the choice mode is wrong.

**Remediation:**
1. Match consumption mode to the economic and authorization meaning of the right.
2. Treat `nonconsuming` on value-moving or approval-granting choices as suspicious by default.
3. Audit failure behavior for `preconsuming` choices to ensure early archival is safe.

**Related:** `0x0006` (reusable mandates), `0x0018` (double-claim prevention)
