# Security Audit

Structured security audit checklists for blockchain and smart-contract systems. This plugin currently covers two audit families: the **Bitcoin ecosystem** and **DAML smart contracts on Canton**. Each skill is designed for formal audit-style review, using numbered checkpoints, evidence-grounded findings, and explicit scope boundaries.



## Skills

The two subfolders cover meaningfully different audit domains and route to the appropriate specialist checklist:

### `/Bitcoin-Security-Audit` -- Bitcoin Ecosystem Audit Dispatcher

Structured security audit checklists for Clarity smart contracts, PSBT signing flows, Ordinals/BRC-20/Runes marketplaces, BTC staking protocols, and Lightning Network dApps.

A dispatcher (`skills/SKILL.md`) routes requests to the correct Bitcoin audit skill by matching project context and user intent. It never auto-executes and waits for confirmation when multiple Bitcoin domains may apply.

**Included Bitcoin audit skills**:
- `/audit-clarity-general` -- Clarity smart contract audit for Stacks contracts
- `/audit-psbt-security` -- PSBT construction and signing audit for BIP-174 / BIP-370 flows
- `/audit-btc-marketplace-general` -- Ordinals, BRC-20, and Runes marketplace audit
- `/audit-btc-staking-general` -- Babylon-style BTC staking protocol audit
- `/audit-ln-dapp-general` -- Lightning Network dApp audit

**Coverage**:
- Clarity authentication, token transfer authorization, post-condition blind spots, and inter-contract call safety
- PSBT sighash misuse, input/output injection, UTXO verification, fee manipulation, Taproot trust confusion, MuSig2 nonce safety, and finalization integrity
- Ordinals marketplace listing manipulation, inscription UTXO handling, indexer trust, front-running, sniping, and platform trust boundaries
- BTC staking covenant bypasses, EOTS slashing failures, timelock manipulation, delegation trust boundaries, rewards, and checkpoint integrity
- Lightning preimage exposure, payment hash reuse, HTLC state machine flaws, swap non-atomicity, force-close fee budgets, replacement cycling, and watchtower assumptions

**Audit style**: checklist-driven review. Every checkpoint follows a four-stage reasoning structure: Identify vulnerable code, Analyze severity, assess Exploitability with concrete attack scenarios, then Check validation steps.


### `/DAML-Security-Audit` -- DAML on Canton Smart Contract Audit

Security audit for DAML smart contracts deployed on Canton.

**Coverage**:
- Workflow authorization: signatories, controllers, multi-party consent, and nested exercises
- Privacy and visibility: stakeholder sets, divulgence, and need-to-know observer design
- Reference binding: `ContractId`, factory outputs, context propagation, and deterministic selection
- State safety: invariants, input validation, arithmetic, time checks, exception handling, and nonconsuming/preconsuming choices
- Lifecycle correctness: archive-and-recreate flows, state machines, service termination, queues, batches, settlement, and upgrades
- Off-ledger trust boundaries: signed messages, attestations, and external payloads

**Audit style**: workflow-first review. The skill maps each critical path from entry choice through nested exercises, referenced contracts, created contracts, archive-and-recreate transitions, and terminal states before confirming findings.


## Shared Principles

All skills in this plugin share a set of audit ground rules:

- **Evidence-required findings.** A finding is reported only when a concrete reachable code path supports it. Missing checks, unusual patterns, or off-ledger assumptions are tracked as candidates until validated against the workflow.
- **Scope honesty.** Each skill declares what it covers, what it does not, and where a different skill or domain-specific review is required. Partial coverage with clear boundaries is preferred over claimed-but-superficial full coverage.
- **Checklist discipline.** Audits follow numbered checkpoints with consistent validation steps so review coverage is reproducible and gaps are visible.
- **Version and deployment awareness.** Platform semantics can depend on version, network, deployment model, SDK, and off-chain integration context. Each audit records the most credible version signals and marks version-limited checkpoints as applicable or not applicable.
- **Actionable output.** Confirmed findings include severity/rating context, code location, scenario, and recommendation so developers can act on them immediately.


## Findings Output

Audit results are written to `findings.md` at the project root.

Bitcoin ecosystem findings include:

1. **Title** -- `{Issue} Leads To {Outcome}` in title case
2. **Code location** -- `filename-L{start}~L{end}`
3. **Description** -- function purpose, issue, and impacts
4. **Scenario** -- step-by-step attack using fictional actors
5. **Recommendation** -- actionable fix

DAML/Canton findings include:

1. **Title** -- `{Issue} Leads to {Outcome}` in title case
2. **Code location** -- `path/to/File.daml:10-28`
3. **Checkpoint** -- the `0x0000`-style checkpoint that produced the finding
4. **Severity, Likelihood, and Impact** -- derived from the DAML/Canton risk-rating methodology
5. **Rating rationale** -- one sentence explaining likelihood and impact
6. **Description** -- the affected workflow and security impact
7. **Scenario** -- step-by-step exploit path
8. **Recommendation** -- actionable remediation


## Example Workflow

1. Install or load the `Security-Audit` plugin.
2. Invoke the skill matching the target project: `/Bitcoin-Security-Audit` for Bitcoin-ecosystem projects or `/DAML-Security-Audit` for DAML/Canton.
3. Provide the intended audit scope, repository context, version signals, and any relevant off-chain integration details.
4. For Bitcoin projects, confirm which routed skill or skills should execute when multiple domains apply.
5. The selected skill maps critical workflows, walks the relevant checkpoints, validates candidates against reachable paths, and deduplicates findings by root cause.
6. Confirmed findings are written to `findings.md`, with test coverage, trust assumptions, version assumptions, and execution blockers recorded.
