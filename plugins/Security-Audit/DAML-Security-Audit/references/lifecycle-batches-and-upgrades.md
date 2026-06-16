# Lifecycle, Batches, and Upgrades

This reference expands checkpoints `0x0015` through `0x001d`.

## Contents

- `0x0015` Archive-and-recreate invariants
- `0x0016` Stuck, contradictory, or unrecoverable states
- `0x0017` Service termination and dependent lifecycle
- `0x0018` Queued and claimable request flows
- `0x0019` Batch and multi-leg settlement
- `0x001a` Element-wise and pairwise batch validation
- `0x001b` Terminal handling of all processed contracts
- `0x001c` Batch and fan-out bounds
- `0x001d` Smart-contract upgrades

---

## 0x0015-archive-and-recreate-flows-should-preserve-state-machine-invariants

**Description:**
DAML models updates by archiving one contract and creating successor contracts. Security bugs appear when successor state does not preserve balances, parties, deadlines, permissions, identifiers, or uniqueness assumptions that justified the predecessor state.

**Identify:**
1. Locate consuming choices and explicit `archive self` flows that create successor contracts.
2. Review split, merge, transfer, rollover, partial-settlement, and update flows that recreate state rather than mutating fields in place.
3. Identify fields whose continuity matters: amounts, key fields, deadlines, stakeholder sets, approvals, and linkage to other contracts.

**Analyze:**
1. Compare predecessor and successor contracts field by field for quantities, permissions, deadlines, identifiers, and stakeholder sets.
2. Verify that any intentional transformation is explicitly authorized and consistent with the business model.
3. Check whether the transition duplicates rights, drops obligations, widens visibility, or bypasses required intermediate states.

**Remediation:**
1. Audit every archive-and-recreate path as a state-machine transition, not a simple data update.
2. Preserve identity, authorization, and economic invariants across successor state.
3. Review key and stakeholder changes explicitly whenever a successor is created.

**Related:** `0x000f` (invariant enforcement), `0x0016` (stuck states)

---

## 0x0016-state-machines-should-not-enter-stuck-contradictory-or-unrecoverable-states

**Description:**
A workflow can be locally authorized at each step yet still be unsafe overall if legitimate users can become stuck, if mutually exclusive states can coexist, or if rights can be committed in one layer while still being independently releasable in another.

**Identify:**
1. Map multi-step workflows including proposal, acceptance, cancellation, expiry, settlement, recovery, and terminal states.
2. Identify interacting templates that together represent one business process.
3. Review workflows that depend on child contracts, collateral contracts, or sub-rights remaining committed across phases.

**Analyze:**
1. Enumerate reachable states and transitions, including failure and timeout branches.
2. Verify that every reachable state has a coherent next step for at least one authorized party.
3. Check whether parallel choices or independently exercisable child contracts can create contradictory states, deadlock, or fake commitment.
4. Review repeatedly mutable governance or voting objects for liveness DoS. If actors can constantly archive-and-recreate votes, prices, or requests, the protocol may need cooldowns or minimum quiet periods before execution.

**Remediation:**
1. Model full workflows, not isolated choices.
2. Verify success, failure, timeout, and unwind paths for every critical state machine.
3. Treat "committed but still independently releasable" child state as a major red flag.
4. Where execution depends on quiescence, encode rate limits, cooldowns, or minimum-resolution windows rather than assuming cooperative behavior.

**Related:** `0x0015` (archive-and-recreate), `0x0017` (service termination liveness)

---

## 0x0017-service-termination-and-dependent-contract-lifecycle-should-preserve-liveness-and-cleanup-intent

**Description:**
When a root service, agreement, or registry object terminates, the audit should explicitly review which dependent contracts should survive, which should be archived, and whether the remaining system stays operable. This is broader than a simple state-machine issue because shutdown often leaves long-lived dependents behind.

**Identify:**
1. Locate terminate, revoke, decommission, uninstall, shutdown, or offboarding choices.
2. Identify configuration, factory, registry, permission, or asset contracts created or governed by the terminating object.
3. Review migrations, shutdown scripts, and admin-side automation that accompany service termination.

**Analyze:**
1. Determine whether each dependent contract should be archived, preserved, migrated, or disabled when the parent terminates.
2. Verify that teardown order and cleanup logic match the intended long-term lifecycle of outstanding assets and permissions.
3. Check whether users retain a safe exit if the service stops, or whether residual contracts become dangerous or unusable.
4. Review partially completed bridge, onboarding, or proposal flows for rollback or cancellation. A missing user or operator unwind path can leave funds or requests stranded even without a direct theft vector.

**Remediation:**
1. Audit shutdown as its own lifecycle with explicit dependent-state handling.
2. Preserve safe user exits and cleanup of privileged dependents.
3. Treat orphaned authority and unusable survivors as security issues, not just operational issues.
4. Add cancel, withdraw, expire, or rollback choices where intermediate failure would otherwise trap value or leave orphaned proposals.

**Related:** `0x0016` (stuck states), `0x0006` (lock release paths)

---

## 0x0018-queued-and-claimable-request-flows-should-prevent-double-claim-stale-claim-and-permanent-pending-state

**Description:**
Async request models such as queued deposits, delayed redemptions, accepted invites, claimable mint or burn results, and admin-processed queues are vulnerable when status transitions are ambiguous, accepted state is not uniquely bound to the output, or pending items can remain live forever.

**Identify:**
1. Locate request templates with `Pending`, `Accepted`, `Claimable`, `Claimed`, `Cancelled`, `Expired`, or similar lifecycle states.
2. Review queue-processing flows, accept-and-claim workflows, and claim choices that mint, transfer, release, or finalize assets or permissions.
3. Identify request ids, nonces, accepted markers, and any off-ledger processing hooks that select which request to complete.

**Analyze:**
1. Map the request lifecycle from submission through processing, claim, cancellation, expiry, and recovery.
2. Verify that each transition is single-use, uniquely bound to the correct requester and computed result, and protected against replay or duplicate claim.
3. Check whether requests can stay permanently pending, become claimable with stale data, or be claimed against the wrong live object.
4. Review whether confirmations or accepted actions point at mutable parent state that may change before execution, or at contract ids that become obsolete after an unrelated state update.

**Remediation:**
1. Bind accepted or claimable state to the exact instance later claimed.
2. Provide explicit expiry, cleanup, and terminal outcomes for stale pending items.
3. Treat duplicate claim surfaces and weakly bound accepted markers as high-priority findings.
4. Snapshot approved amounts and destinations inside the accepted action itself, and prefer stable business ids over mutable contract ids for long-running confirmations.

**Related:** `0x000a` (reference binding), `0x0014` (nonconsuming replay), `0x0012` (stale expiry)

---

## 0x0019-batch-and-multi-leg-settlement-should-be-atomic-balanced-and-route-safe

**Description:**
Payment and securities systems often settle through batches, routed instructions, DvP or PvP legs, or intermediary chains. These flows are safe only if every leg is bound into one atomic outcome or if partial-progress behavior is explicitly safe and recoverable.

**Identify:**
1. Locate batch settlement, route-based transfer, DvP, PvP, allocation, split-transfer, or intermediary-driven workflows.
2. Identify every leg, instrument, counterparty, intermediary, and route-selection input involved in the final business outcome.
3. Review whether settlement happens in one transaction tree or through staged claim-and-complete steps.

**Analyze:**
1. Determine what must happen for the business outcome to be considered complete.
2. Verify whether the implementation is truly atomic, or whether any leg can finalize, fail, or be observed independently in a way that breaks all-or-nothing intent.
3. Recompute the authorization and visibility requirements for every leg that must succeed, including fee legs, change legs, cancellation legs, and cleanup legs. A flow is not atomic in practice if one auxiliary leg can fail under the intended outer authorization context.
4. Check whether route selection, intermediary state, or stale inputs can redirect value or leave partial execution that is not explicitly safe.

**Remediation:**
1. Verify atomicity assumptions across the full settlement graph.
2. Audit route selection and intermediary trust as part of settlement correctness.
3. Build a per-leg authorization matrix for multi-leg settlement and require that every mandatory leg is executable under the documented workflow without hidden extra authorizers.
4. Treat any partially finalized economic outcome as a potential high-severity issue unless it is explicitly recoverable.

**Related:** `0x001a` (element-wise batch validation), `0x0011` (arithmetic conservation)

---

## 0x001a-batch-validation-should-be-element-wise-and-pairwise-not-just-aggregate

**Description:**
Batch validation often fails when code proves something about the collection as a whole rather than about each element or each required pairwise relation. One valid item can mask an invalid duplicate, same-side, same-owner, stale, or incompatible item.

**Identify:**
1. Locate batch matching, routing, grouping, or settlement choices over lists, maps, or sets of contracts.
2. Review predicates built with `all`, `any`, counts, aggregate booleans, or one top-level validation pass followed by per-item processing.
3. Identify pairwise rules such as side, owner, asset, counterparty, price, or status compatibility.

**Analyze:**
1. Determine which rules must hold per element, per pair, or per subgroup rather than only for the batch aggregate.
2. Verify that validation is enforced at the right granularity and again inside helpers that process individual members after a batch precheck.
3. Construct a mental mixed batch with one valid element and one invalid element and check whether the invalid element can still ride through.

**Remediation:**
1. Validate every element individually and every required relation between elements.
2. Treat aggregate predicates as suspicious when the business rule is pairwise or per-item.
3. Add mixed-batch reasoning to every batch audit, not just happy-path aggregate checks.

**Related:** `0x0019` (batch atomicity), `0x001b` (batch outcome completeness)

---

## 0x001b-batch-outcomes-should-terminally-handle-and-accurately-represent-all-processed-contracts

**Description:**
Batch workflows are unsafe if only the root contract is consumed, if processed inputs remain live, or if the recorded completion result copies metadata from only a representative element. The ledger must faithfully represent which contracts were economically finalized.

**Identify:**
1. Locate batch choices exercised on one contract with additional `[ContractId]` inputs or helper-returned collections.
2. Review processing flows that move value or finalize many contracts but archive only one root or representative contract.
3. Identify aggregate receipt, completion, or summary contracts created from many processed inputs.

**Analyze:**
1. Determine which contracts are economically processed by the batch, not just which one is exercised.
2. Verify that every processed contract is consumed, archived, superseded, or explicitly left in a safe retry state.
3. Check whether the resulting aggregate record faithfully represents the full processed set rather than only a representative element or partial metadata subset.

**Remediation:**
1. Audit economic finality across every processed input, not just the root exercised contract.
2. Ensure aggregate outcomes record all relevant processed items or create clear per-item terminal state.
3. Treat stale live processed contracts as both replay risk and auditability risk.

**Related:** `0x001a` (element-wise validation), `0x0018` (double-claim)

---

## 0x001c-batch-and-fan-out-logic-should-be-bounded-and-auditable

**Description:**
Large list processing, massive observer sets, and wide fan-out transaction trees can create denial of service, privacy blow-up, or operability failure, especially on Canton where informee growth matters.

**Identify:**
1. Locate folds or loops over `[Party]`, `[ContractId]`, maps, sets, and user-controlled collections.
2. Review large batch choices, fan-out creates, mass notification patterns, and dynamic disclosure lists.
3. Identify where user input controls transaction size, output count, or stakeholder growth.

**Analyze:**
1. Determine worst-case transaction size, informee growth, and object explosion for each fan-out flow.
2. Verify that collections are bounded, validated, deduplicated, and chunked where appropriate.
3. Check whether the protocol preserves auditability of what happened to each element or becomes too large to inspect reliably.

**Remediation:**
1. Bound fan-out and batch sizes explicitly.
2. Review disclosure growth together with computational growth.
3. Ensure outputs remain durable and auditable even at worst-case supported scale.

**Related:** `0x0007` (observer sets), `0x001a` (batch validation)

---

## 0x001d-smart-contract-upgrades-should-preserve-authorization-privacy-and-state-compatibility

**Description:**
On Canton, upgrades are a security category because new package versions can change controllers, observers, choice bodies, and interface behavior while old contracts remain live. Unsafe upgrades can silently widen power, alter privacy, or create divergent behavior between legacy and upgraded instances.

**Identify:**
1. Locate package upgrade plans, migration code, SCU-compatible changes, and versioned modules.
2. Review changed controllers, observers, `ensure` clauses, choice parameters, and interface implementations across versions.
3. Identify off-ledger systems that assume old and new contract versions behave the same.

**Analyze:**
1. Compare old and new authorization, privacy, business invariants, and data-shape assumptions for active contracts.
2. Verify whether already-live contracts and dependent automation remain safe under the new package.
3. Check whether old and new versions can coexist in contradictory ways or create silent semantic drift without an explicit migration.

**Remediation:**
1. Treat upgrade review as a security review, not a compatibility-only review.
2. Compare old and new behavior at the authorization, privacy, and state-machine level.
3. Require explicit migration and revalidation when semantics change.

**Related:** `0x0009` (interface drift), `0x0004` (off-chain trust boundaries)
