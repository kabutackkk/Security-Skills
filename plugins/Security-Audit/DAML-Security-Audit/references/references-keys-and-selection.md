# References, Keys, and Deterministic Selection

This reference expands checkpoints `0x000a` through `0x000e`.

Version applicability note:
Checkpoints `0x000b` and `0x000c` are only fully applicable when the target project and runtime actually support or still use contract keys. In newer DAML/Canton stacks, contract-key support may be deprecated, unsupported, or intentionally absent. In that case, mark the checkpoint `Not Applicable` unless legacy code, migration code, old tests, or surrounding documentation still rely on key semantics.

## Contents

- `0x000a` Referenced contracts and business-context rebinding
- `0x000b` Contract-key and maintainer design
- `0x000c` Key-based operations and negative lookups
- `0x000d` Context propagation and helper outputs
- `0x000e` Deterministic selection and role assignment

---

## 0x000a-referenced-contracts-should-be-fetched-and-validated-against-business-context

**Description:**
Even when types line up, a user-supplied `ContractId` may refer to the wrong business object. Fetching a visible contract is not enough; the fetched data must be rebound to the current workflow context before it is trusted.

**Identify:**
1. Locate every choice argument or template field that carries a `ContractId` or stores a later-used reference.
2. Review `fetch`, `exercise`, `exerciseByKey`, archival helpers, and successor contracts that copy references forward.
3. Pay special attention to workflows that treat a referenced lock, permit, allocation, invite, or result contract as committed collateral for a later parent workflow.

**Analyze:**
1. Identify what the reference is supposed to mean in business terms: specific counterparty, specific amount, specific request instance, specific nonce, or specific state transition.
2. Verify that the referenced contract is validated against the current workflow context at each step where it matters, including parties, identifiers, state, liveness, uniqueness, and quantity relationships.
3. For nested exercises, compute the downstream controller set from the fetched contract and confirm the outer workflow can satisfy that authorization set for all allowed parameterizations.
4. Check whether a long-running workflow should be bound to a stable business identifier or a specific contract instance. Using a mutable `ContractId` where the workflow really means "this account regardless of successor state" can break parallel or delayed confirmations.
5. The exploit path is: an attacker supplies a visible `ContractId` of the correct type but from the wrong business context, causing settlement, permission checks, or configuration lookups to proceed against the wrong object.

**Remediation:**
1. Re-bind every referenced contract to the exact business object required by the choice before using it.
2. Do not rely on template type alone when the workflow really needs instance identity.
3. Re-check liveness and exclusivity assumptions whenever a referenced contract is used across phases.
4. Snapshot the fields that governance or processors are actually approving (amount, destination) instead of re-reading mutable parent state at execution time.

**Related:** `0x000d` (context propagation), `0x0018` (stale claim binding)

---

## 0x000b-contract-keys-and-maintainers-should-reflect-real-ownership-of-uniqueness

**Description:**
Contract keys are namespace controls. The key fields define what is supposed to be unique, and the maintainers effectively own the right to assert and manage that uniqueness. If either is wrong, the ledger's uniqueness model diverges from the business model.

If the project version does not support contract keys, or the codebase does not use them, treat this checkpoint as version-limited and focus instead on whether the design has replaced keys with explicit on-ledger identifiers, trusted off-ledger uniqueness, or migration logic that could drift from the old key model.

**Identify:**
1. Review all `key` and `maintainer` clauses.
2. Search for comments or code paths that avoid keys and instead rely on command deduplication, API checks, operator discipline, or "latest event" lookups.
3. Identify logical singletons, registries, account-like objects, names, positions, approvals, or request identifiers that the application treats as unique.

**Analyze:**
1. Determine the real-world namespace each key is supposed to protect.
2. Verify that the key fields cover the full uniqueness domain and that the maintainer set corresponds to the parties who genuinely own or control that namespace.
3. Check whether the system assumes on-ledger uniqueness for an object that the ledger does not actually key, or keys in a weaker domain than the business logic expects.

**Remediation:**
1. Use on-ledger keys whenever the protocol requires true uniqueness rather than best-effort deduplication.
2. Make maintainers reflect actual ownership of the namespace.
3. Flag "operational uniqueness" as a trust-boundary assumption, not a substitute for a key.

**Related:** `0x000c` (Canton key scope), `0x0004` (off-chain trust boundaries)

---

## 0x000c-key-based-operations-and-negative-lookups-should-respect-canton-scope-and-authority

**Description:**
On Canton, key visibility and uniqueness are scoped by authority and topology. A negative `lookupByKey`, `fetchByKey`, or `visibleByKey` result is not automatically proof of global absence, and key-based operations are not safe if the design assumes network-wide visibility that does not exist.

If the target DAML/Canton version does not support these key-based operations in the deployed path, mark this checkpoint `Not Applicable` for live code and limit review to legacy code, migration assumptions, stale tests, or documentation that still treats keys as an active safety mechanism.

**Identify:**
1. Locate all `fetchByKey`, `lookupByKey`, `visibleByKey`, and `exerciseByKey` operations.
2. Review create-if-missing flows, anti-duplication checks, key-based singleton access, and any branch that treats `None` or `False` as proof a conflicting contract does not exist.
3. Identify workflows whose safety depends on key operations behaving like a globally visible registry.

**Analyze:**
1. Determine what authority and visibility assumptions each key-based operation relies on.
2. Check whether negative results could be caused by missing stakeholder visibility, missing maintainer authority, or Canton deployment scope rather than by actual global absence.
3. Verify that the design tolerates Canton-specific key semantics and does not treat participant-local views as universal truth.
4. The exploit path is: a workflow treats `None`/`False` from a key lookup as proof of global absence, then creates or exercises against the wrong object once deployment topology differs from local test assumptions.

**Remediation:**
1. Audit every negative key lookup under Canton visibility rules, not generic DAML intuition.
2. Avoid using key absence as proof of safety unless the authority and scope really support that conclusion.
3. Treat key-based convenience selectors as security-critical when they determine uniqueness or identity.

**Related:** `0x000b` (key/maintainer design), `0x000a` (reference validation)

---

## 0x000d-context-propagation-and-factory-results-should-be-validated-end-to-end

**Description:**
Complex DAML workflows often thread context records, maps, allocation outputs, transfer results, or helper-produced payloads across multiple modules. Bugs appear when downstream steps assume those results are well-formed, ordered, singleton, or still context-consistent without validating them at the final point of use.

**Identify:**
1. Locate factory choices, helper modules, utility functions, and rules contracts that return structured outputs used later.
2. Review `Context` records, `Map` or `TextMap` propagation, list outputs, grouped results, and helper functions that return multiple contracts or references.
3. Find code that uses `head`, `last`, `take 1`, list indexing, zipping parallel lists, or "first result" query patterns without explicit sorting on contract fields.

**Analyze:**
1. Trace critical fields end to end from user input or upstream contract through helpers to the final binding create or exercise.
2. Verify shape, cardinality, identity, ordering, and alignment assumptions at each boundary rather than assuming singleton or stable order.
3. Check whether caller-controlled or helper-produced values are forwarded into binding contracts without revalidation at the exact step where they affect authorization or economics.
4. When helpers create multiple child contracts or auxiliary legs, compare user-facing metadata against the authoritative child-contract state field by field. Watch for desynchronization between displayed receiver, sender, asset, amount, executor, deadline, or fee data and the actual child contracts later exercised.
5. Audit confirmation workflows for "vote now, materialize later" drift: if the approved action reads mutable account state at execution time, the voted-over effect may differ from the effect that actually executes.

**Remediation:**
1. Validate factory and helper outputs at each boundary, not just at the source.
2. Reject implicit reliance on list order or singleton shape unless it is explicitly enforced.
3. Re-check propagated context when it becomes binding for authorization or economic effect.
4. When helper-created child contracts become the authoritative settlement objects, derive user-facing metadata from those child contracts or assert full equality before exposing or binding the workflow.
5. Prefer immutable action payloads over deferred reads from mutable parent contracts in multi-step governance or queue workflows.

**Related:** `0x000a` (reference validation), `0x000e` (deterministic selection)

---

## 0x000e-order-matching-priority-and-role-assignment-should-be-deterministic-and-enforced-at-execution

**Description:**
Matching engines, queue selectors, and best-offer logic are security-relevant in DAML because fairness, expiry, and role assignment depend on deterministic selection. If ordering depends on participant-local query order or stale off-ledger views, users can receive inconsistent execution or unfair priority.

**Identify:**
1. Locate order books, matchers, selectors, queues, best-offer logic, and any workflow that chooses one record from many.
2. Review sorting, filtering, and tie-breaking logic, especially code that selects the `first`, `oldest`, or "best" candidate from an unordered query result.
3. Identify maker/taker, initiator/counterparty, or winner/loser role assignments that depend on the selected record.

**Analyze:**
1. Determine which fields are meant to establish priority, expiry, and role assignment.
2. Verify that those fields are derived deterministically from on-ledger state, with explicit sorting when order matters, and revalidated at the exact exercise that finalizes the match.
3. Check whether concurrent submissions, stale views, or ambiguous tie-breaking can change which candidate is chosen or which side receives privileged execution status.
4. Review whether the workflow tallies or resolves as soon as quorum is reached even though additional in-flight votes or confirmations could still change the winner or selected action.

**Remediation:**
1. Make selection criteria explicit, deterministic, and execution-time enforced.
2. Reject reliance on participant-local query order for fairness-sensitive logic.
3. Audit role assignment together with candidate selection, because both are part of the same security property.
4. If early resolution is allowed, justify it explicitly; otherwise require a minimum collection period or finalization condition before tallying.

**Related:** `0x000d` (context propagation), `0x0001` (controller authorization)
