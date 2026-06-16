---
name: DAML-Security-Audit
description: Security audit for DAML smart contracts on Canton, focused on workflow authorization, privacy, lifecycle, and finance-oriented state safety.
---

# DAML on Canton Security Audit

## Overview

This skill audits DAML smart contracts deployed on Canton. The main DAML failure mode is rarely syntax. It is mismatch between the intended workflow and what the ledger actually authorizes, discloses, preserves, replays, expires, or binds to a specific contract instance.

Unlike EVM-style audits, this review is not centered on reentrancy, gas griefing, or arbitrary shared-state mutation inside a globally visible account model. DAML is a workflow language for multi-party business processes. It models rights, obligations, approvals, and facts directly, with choices as the main transition surface and with multiple actions often composed into one transaction. DAML also treats privacy and authorization as first-class language features: stakeholders, signatories, observers, and controllers determine who can see data and who can advance state, rather than leaving all of that to ad hoc application logic.

This leads to a different audit lens from typical Solidity-style systems. EVM contracts usually operate against a single transparent global state and rely on manually written authorization checks around general-purpose functions and variables. DAML instead gives each party a scoped view of the ledger, records business relationships directly, and automatically enforces many visibility and authorization constraints. The main failures therefore tend to come from weak business binding, incorrect stakeholder sets, unsafe delegation, stale references, archive-and-recreate drift, or misplaced trust in off-ledger orchestration.

Canton adds its own peculiarity on top of DAML. DAML code is designed to be portable across ledger backends, but on Canton the audit must reason about synchronizers, participant-local views, disclosure, reassignment, and topology-sensitive behavior. That makes version-specific and deployment-specific semantics more important than in many chain-specific smart-contract reviews.

This matters because DAML and Canton are commonly used for financial and regulated workflows. Financial institutions use them for tokenized assets such as bonds, real estate interests, cash-like instruments, and wallet-based business flows that must manage multiple asset types under explicit transfer and ownership rules. Insurers use DAML to automate policy administration and claims so that coded terms, approvals, and payout conditions are shared across the relevant parties. Capital-markets workflows use DAML and Canton for trade capture, clearing, settlement, custody coordination, and regulator-facing reporting where brokers, custodians, operators, and counterparties must stay synchronized on the same lifecycle state. The audit should therefore treat authorization splits, confidentiality, lifecycle correctness, atomicity, and off-ledger operational assumptions as core security properties, not secondary business logic concerns.

The review reasons about:

- who can exercise each choice
- who can see each contract and exercise
- whether referenced contracts, keys, and selections are bound to the intended business object
- whether archive-and-recreate transitions preserve state-machine and accounting intent
- which guarantees are enforced on-ledger versus delegated to operators, automation, APIs, or participant-local views

### Scope

Audit DAML and Canton code for:

- Missing consent and unauthorized state transitions
- Visibility leaks through observers, divulgence, or interface views
- Incorrect reference, key, and context binding
- Broken invariants, time checks, arithmetic, and exception handling
- Replayable or inconsistent lifecycle transitions
- Batch-settlement and queue-processing flaws
- Upgrade, attestation, and off-ledger trust-boundary risks

### Out of Scope

This skill does **not** cover:

- Canton node configuration, sequencer tuning, or domain topology management
- JSON API / gRPC Ledger API server hardening
- Network-level security, TLS, or participant identity provisioning
- Non-DAML smart-contract languages or general Scala/Java code that does not prepare DAML commands
- Performance, gas, or resource-consumption analysis

## When to Use

**Triggers** -- use this skill when the codebase contains any of:

- `.daml` files or a `daml.yaml`
- `template`, `choice`, `nonconsuming`, `preconsuming`, `ensure`
- `signatory`, `observer`, `controller`
- `key`, `maintainer`, `fetchByKey`, `lookupByKey`, `visibleByKey`, `exerciseByKey`
- `create`, `createAndExercise`, `exercise`, `fetch`, `archive`
- `interface`, `viewtype`, `interface instance`, `toInterface`
- `assert`, `assertMsg`, `abort`, `throw`, `try`, `catch`
- `getTime`, expiry windows, or effective-date logic
- Proposal, approval, permit, delegation, lock, release, or claim flows
- Dynamic `[Party]`, `[ContractId]`, `Map`, or `Set` driven authorization or visibility logic
- Canton visibility, multi-party authorization, contract keys, or archive-and-recreate workflows

**Do not use this skill when:**

- the task is mainly Canton node operations, domain topology, sequencer tuning, or participant deployment
- the review is a generic backend, API, or infrastructure audit with no material DAML workflow effect
- the target is an EVM, Solidity, Move, or other non-DAML smart-contract system
- the user only wants language syntax help or routine DAML development guidance rather than a security review

## Risk Rating

Every confirmed finding must state:

- `Severity`
- `Likelihood`
- `Impact`

Use [risk-rating-methodology.md](references/risk-rating-methodology.md) as the primary rating guide. It defines how to derive final severity from DAML/Canton-specific likelihood and impact.

Definitions:

- `Likelihood`: how realistically the vulnerability can be reached and exploited in the deployed workflow, given the actual attacker, required preconditions, and existing controls.
- `Impact`: the expected harm if exploitation succeeds, measured across asset safety, authorization, privacy, governance, accounting correctness, and liveness.
- `Severity`: the final risk classification derived from likelihood and impact, used to communicate priority and audit significance.

For level definitions, decision rules, and the severity matrix, read `references/risk-rating-methodology.md` instead of improvising from intuition.

## References

Load the full reference set before forming findings. Many real findings surface under checkpoints that seem unrelated to the initial code surface; lazy loading risks missing them.

- [authorization-and-visibility.md](references/authorization-and-visibility.md) -- checkpoints `0x0000`--`0x0009`
- [references-keys-and-selection.md](references/references-keys-and-selection.md) -- checkpoints `0x000a`--`0x000e`
- [invariants-inputs-and-time.md](references/invariants-inputs-and-time.md) -- checkpoints `0x000f`--`0x0014`
- [lifecycle-batches-and-upgrades.md](references/lifecycle-batches-and-upgrades.md) -- checkpoints `0x0015`--`0x001d`
- [external-payloads-and-tests.md](references/external-payloads-and-tests.md) -- checkpoints `0x001e`--`0x001f`
- [risk-rating-methodology.md](references/risk-rating-methodology.md) -- likelihood, impact, and final severity methodology

If any reference file is missing, stop and report the missing file before proceeding.

## Steps

Run these steps sequentially in a single agent context. Findings require a coherent global view of authorization, visibility, and state flow -- parallel or multi-agent splitting breaks that coherence.

### Step 1. Discover Scope

Identify the in-scope DAML modules and adjacent off-ledger code that materially affects DAML behavior.

**Produce:**
- Sorted DAML file list
- Related backend, automation, wallet, API, and test files
- Discovered test directories, script suites, and likely test commands
- Detected DAML/Canton version signals and any version uncertainty
- Explicit audit boundary

**Rules:**
- Start from `.daml` modules in scope.
- Include adjacent TypeScript, backend, automation, or test code when it prepares commands, chooses references, controls sequencing, or compensates for missing on-ledger checks.
- If the target folder has a `test`, `tests`, `spec`, `scripts`, or DAML-script-style directory, identify the local test entry points and how they run.
- Detect the most credible DAML/Canton version signal available from `daml.yaml`, `dpm.yaml`, package metadata, CI config, lockfiles, docs, or build scripts.
- Record uncertainty if the exact version cannot be established. Do not silently assume contract-key or exception behavior is the same across DAML generations.
- If the user gives a narrower scope, honor it, but note material off-ledger dependencies.
- If the project includes a design doc, white paper, or architecture note, use it when evaluating intended workflow.

**Success criteria:**
- The audit boundary is explicit, adjacent off-ledger dependencies are named, and the most credible DAML/Canton version signal is recorded.

### Step 2. Load References

Load all six reference files listed in the References section above. Confirm each file is present. Build:

- a checkpoint coverage plan mapping `0x0000`--`0x001f` to the in-scope templates and choices
- a version-applicability plan for checkpoints that depend on DAML/Canton feature availability, especially contract-key and exception checkpoints

**Success criteria:**
- Every required reference file is confirmed present, every checkpoint has an intended review target or a clean `Not Applicable` reason, and version-limited checkpoints are identified before scanning.

### Step 3. Build Workflow Maps

Reconstruct critical execution and state-transition paths before classifying findings.

**Produce:**
- Workflow map per critical feature
- State-transition notes
- Authorization and visibility notes
- Leg-by-leg authorization matrix for nested exercises and auxiliary child contracts when the flow has multiple legs or optional branches

**Rules:**
- For each critical flow, map: entry template or choice -> controller and stakeholder set -> referenced contracts, keys, and factory outputs -> nested `fetch`, `exercise`, `create`, and archive-and-recreate transitions -> time, expiry, queue, and terminal-state behavior.
- For every nested `exercise` on a referenced child contract or interface, recompute the child contract's actual controller set and visibility requirements from the child contract itself, not from the parent workflow narrative.
- Do this separately for main legs, fee legs, change legs, cancellation paths, refund paths, optional branches, and helper-produced auxiliary contracts. Do not stop after checking only the economically primary leg.
- Reason from reachable end-to-end workflows, not isolated template snippets.

**Success criteria:**
- Each critical feature has an end-to-end workflow map detailed enough to support checkpoint review and later exploit-path validation, including a clear answer to whether the intended outer authorization context can satisfy every downstream child-contract exercise it relies on.

### Step 4. Candidate Scan

Run a full checkpoint-based candidate pass across `0x0000`--`0x001f`.

**Produce:**
- Candidate findings, each tagged with the checkpoint ID it maps to
- Checkpoint coverage notes (which checkpoints yielded candidates, which were clean)

**Rules:**
- Do not stop after the first plausible issue category. Complete the full pass.
- Record weak candidates during this pass; do not prematurely drop them.
- Include on-ledger and off-ledger split issues when the invariant spans both layers.

**Success criteria:**
- All checkpoints `0x0000`--`0x001f` are accounted for with either candidate findings, clean coverage notes, or version-based non-applicability.

### Step 5. Validate Candidates

Validate each candidate against the exact code path and business context.

**Produce:**
- Confirmed findings (with severity, likelihood, and impact per the risk-rating methodology)
- Dropped candidates with reason
- Explicit trust assumptions

**Rules -- confirm or drop:**
- For each candidate, decide: confirmed finding, dropped candidate, or design tradeoff / accepted trust assumption.
- Re-check: exact choice path; object identity and reference binding; whether the issue is ledger-enforced or only prevented operationally; whether the behavior is intended and safe under the documented trust model.

**Rules -- false-positive reduction:**
- Do not report a finding until the specific choice path, state transition, or reference-binding failure is identified.
- Do not treat off-ledger behavior as a fix. If safety depends on operator discipline, command ordering, automation sequencing, or API-side filtering, treat that as a trust-boundary condition and assess it explicitly.
- When a workflow relies on nested exercises against child contracts or external interfaces, verify authorization closure leg by leg. If the parent path only works because off-ledger submission adds extra `actAs` or `readAs` parties not documented by the business flow, record that as a trust-boundary dependency or finding rather than silently assuming the parent authorization is sufficient.
- For duplicate-state, replay, or misbinding candidates: verify who can actually create the conflicting state. If the design assigns uniqueness enforcement to a trusted controller and untrusted parties cannot force a conflicting state, record it as a trust assumption, not a vulnerability. When exact `ContractId` binding is intentionally avoided, check whether a stable business key plus trusted off-ledger coordination by the same authority substitutes. Only escalate if an untrusted actor can exploit the substitution or it creates cross-party harm.
- For controller self-harm paths: do not report as a security finding unless the blast radius harms another party, breaks a protocol-wide invariant that others rely on, or leaks state to observers outside the controller's own stakeholder set. "Trust domain" here means the set of parties whose contracts and visibility are affected solely by that controller's own actions.
- If the issue depends on concurrency, ordering, stale state, or long-running confirmations, validate that path explicitly.

**Success criteria:**
- Every retained finding has a concrete reachable path, every dropped candidate has a reason, and every material trust-boundary dependency is stated explicitly.

### Step 6. Review and Run Tests

Use the target project's existing test surface as validation evidence.

**Rules:**
- If the target folder includes tests, review relevant tests before finalizing findings.
- If there is a project-native way to run the relevant tests, run them and record the outcome.
- Passing tests are coverage evidence, not proof of safety.
- Failing tests: if the failure reproduces a candidate finding, record it as supporting evidence. If the failure is unrelated (environment, dependency, version skew), record the blocker and do not let it gate the audit.
- If tests cannot be run, state the specific blocker.
- Note existing test templates, helpers, and naming conventions for potential PoC use.

**Success criteria:**
- Relevant existing tests are reviewed, runnable tests are executed when feasible, and every test result or blocker is recorded in a way that supports the final report.

### Step 7. Deduplicate

Merge overlapping findings by root cause.

- Keep the strongest version when two findings share the same root cause.
- Preserve separate findings when they differ by exploit mechanism, affected workflow stage, or local remediation.
- Do not collapse a reference-binding bug into a generic stale-state bug if the exploit path and fix differ materially.

**Success criteria:**
- The final finding set is free of root-cause duplicates, while materially different exploit paths remain separate.

### Step 8. Report

Produce the final audit result from the validated, deduplicated set.

**Include:**
- Scope audited
- Confirmed findings sorted by severity then confidence, or `No findings.`
- `Likelihood`, `Impact`, and one-sentence rating rationale for each confirmed finding
- Exploitability rationale for each finding
- Test coverage reviewed, tests run, and execution blockers (if any)
- Material uncertainty, trust assumptions, or testing gaps
- Version assumptions and any checkpoints marked not applicable because the target DAML/Canton version does not support that feature
- If confirmed high-severity findings exist, ask the user whether they want PoC tests generated using the project's existing test template and style before creating new test files.

**Success criteria:**
- The final report can be read without reopening the working notes: scope, validated findings, rating rationale, test evidence, and version assumptions are all present in the output.

## Output Format

Write confirmed findings to `findings.md` in the project root. If this file already exists, append under a run header:

```md
---

# Audit Run — {YYYY-MM-DD}

Scope: {brief scope description}
```

### Finding Template

```md
## {Issue Description} Leads to {Outcome}

`path/to/File.daml:10-28`
`Checkpoint: 0x0000-some-checkpoint-name`

**Severity:** High
**Likelihood:** Medium
**Impact:** High
**Rating Rationale:** Reachable by an authenticated counterparty on the normal acceptance path, with cross-party settlement impact.

**Description:** `SomeChoice` creates or exercises ...

**Scenario:**
1. Alice ...
2. Then Bob ...
3. Then the operator ...

**Recommendation:** ...
```

### Formatting Rules

- **Title:** capitalize using standard title case (capitalize major words; lowercase articles, short prepositions, and conjunctions unless they start the title).
- **Code location:** use `path/to/File.daml:10-28` (colon + hyphen, standard format). For findings spanning DAML and off-ledger code, list the primary DAML location first, then the off-ledger location on the next line.
- **Checkpoint tag:** place directly below the code location as `Checkpoint: 0x0000-some-checkpoint-name`. Every finding must cite the checkpoint it maps to (recorded during the candidate scan in Step 4).
- **Rating block:** include `Severity`, `Likelihood`, and `Impact` before the finding description. Base them on `references/risk-rating-methodology.md`, not intuition.
- **Rating rationale:** add one sentence explaining why the chosen likelihood and impact are justified in this DAML/Canton workflow.
- **Description:** state the purpose of the relevant template/choice/workflow, identify the issue precisely, and outline impacts.
- **Scenario:** use numbered steps with fictional users (Alice, Bob, operator, etc.).
- **Recommendation:** concise and actionable. Prefer on-ledger fixes. If the current design depends on off-ledger sequencing, say so explicitly.
- Keep descriptions concise. Prefer short narrative over bullet-heavy prose.
- Enclose functions, choices, templates, and variables in backticks.

## Checklist

Each checkpoint maps to a detailed entry in `references/`.

### A. Authorization, Visibility, and Trust Boundaries (`0x0000`--`0x0009`)

- `0x0000-obligated-parties-should-be-signatories`
- `0x0001-choice-controllers-should-be-visible-and-business-authorized`
- `0x0002-privileged-role-transfers-should-use-safe-handshake-patterns`
- `0x0003-credential-permit-and-delegation-patterns-should-be-scoped-revocable-and-action-bound`
- `0x0004-privileged-roles-and-offchain-trust-boundaries-should-be-explicitly-audited`
- `0x0005-holding-custody-and-signatory-model-should-match-the-intended-trust-model`
- `0x0006-locks-preapprovals-and-recurring-mandates-should-be-bounded-revocable-and-safely-releasable`
- `0x0007-observer-sets-should-follow-need-to-know`
- `0x0008-choice-visibility-and-divulgence-should-be-explicitly-reviewed`
- `0x0009-interfaces-and-views-should-not-hide-authorization-or-leak-data`

### B. References, Keys, and Deterministic Selection (`0x000a`--`0x000e`)

- `0x000a-referenced-contracts-should-be-fetched-and-validated-against-business-context`
- `0x000b-contract-keys-and-maintainers-should-reflect-real-ownership-of-uniqueness`
- `0x000c-key-based-operations-and-negative-lookups-should-respect-canton-scope-and-authority`
- `0x000d-context-propagation-and-factory-results-should-be-validated-end-to-end`
- `0x000e-order-matching-priority-and-role-assignment-should-be-deterministic-and-enforced-at-execution`

### C. Invariants, Inputs, Arithmetic, Time, and Exceptions (`0x000f`--`0x0014`)

- `0x000f-template-and-choice-invariants-should-be-enforced-on-ledger`
- `0x0010-inputs-and-choice-arguments-should-be-validated-against-business-rules`
- `0x0011-arithmetic-rounding-and-unit-conversions-should-preserve-economic-intent`
- `0x0012-time-based-rights-and-expiry-should-be-enforced-at-choice-time`
- `0x0013-exception-handling-and-rollback-should-not-mask-security-failures`
- `0x0014-nonconsuming-and-preconsuming-choices-should-match-economic-intent`

### D. Lifecycle, State Machines, Settlement, and Upgrades (`0x0015`--`0x001d`)

- `0x0015-archive-and-recreate-flows-should-preserve-state-machine-invariants`
- `0x0016-state-machines-should-not-enter-stuck-contradictory-or-unrecoverable-states`
- `0x0017-service-termination-and-dependent-contract-lifecycle-should-preserve-liveness-and-cleanup-intent`
- `0x0018-queued-and-claimable-request-flows-should-prevent-double-claim-stale-claim-and-permanent-pending-state`
- `0x0019-batch-and-multi-leg-settlement-should-be-atomic-balanced-and-route-safe`
- `0x001a-batch-validation-should-be-element-wise-and-pairwise-not-just-aggregate`
- `0x001b-batch-outcomes-should-terminally-handle-and-accurately-represent-all-processed-contracts`
- `0x001c-batch-and-fan-out-logic-should-be-bounded-and-auditable`
- `0x001d-smart-contract-upgrades-should-preserve-authorization-privacy-and-state-compatibility`

### E. External Inputs and Assurance (`0x001e`--`0x001f`)

- `0x001e-attestations-nonces-and-external-payloads-should-be-bound-to-ledger-actions`
- `0x001f-negative-authorization-and-privacy-cases-should-be-covered-by-daml-script`
