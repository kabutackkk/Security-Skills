---
name: audit-clarity-general
description: Audits Clarity smart contracts for authentication model misuse, token transfer authorization gaps, SIP compliance, post-condition blind spots, error handling, and inter-contract call safety. Produces a findings.md report with ranked vulnerabilities.
when_to_use: |
  Use when user mentions "clarity audit", "stacks audit", "clarity contract", "stx", "clarity security", "tx-sender", "contract-caller", "as-contract", "post-conditions", "SIP-010", "SIP-009", "SIP-013", "clarity vulnerability", "stacks vulnerability", "@stacks/transactions", "@stacks/connect", "makeContractCall", "PostConditionMode", "standardPrincipalCV", or asks about Clarity language-level security, authentication model, Stacks smart contract best practices, or Stacks SDK TypeScript security.
  Do NOT use for Solidity/EVM, Rust/Soroban, or Bitcoin Script contracts.
allowed-tools:
  - Read
  - Grep
  - Glob
  - Write
arguments:
  - target
argument-hint: "[file, directory, or description of code to audit]"
# context: inline (user interaction needed for findings review)
---

# Clarity Smart Contract Vulnerability Scanner

## 1. Introduction

This skill audits Clarity smart contracts on the Stacks blockchain for language-level security vulnerabilities. Clarity's design — interpreted execution, no reentrancy, explicit post-conditions — eliminates several EVM vulnerability classes but introduces unique risks around its principal-based authentication model, `as-contract` context switching, post-condition blind spots, and inter-contract call trust boundaries.

Real-world incidents informing this checklist:
- **Charisma** (Sep 2024, 183k STX): `as-contract` principal elevation via error-path context retention
- **Zest Protocol** (Apr 2024, 322k STX): List parameter duplication inflating collateral values
- **Arkadiko Swap** (Oct 2021, ~$1.5M): LP token validation failure in swap contract
- **ALEX Protocol** (Jun 2025, $8.3M): Self-listing verification logic vulnerability

## 2. Purpose

This skill audits Clarity contracts to detect vulnerabilities in:

- Authentication model misuse (`tx-sender` vs `contract-caller` vs `as-contract`)
- Token transfer authorization gaps in `ft-transfer?`, `nft-transfer?`, `stx-transfer?`
- SIP standard compliance (SIP-009, SIP-010, SIP-013)
- Post-condition limitations and blind spots
- Error handling patterns that create DoS or logic bypass vectors
- Inter-contract call safety and trait reference validation
- State management semantics (`map-set` vs `map-insert`)
- Governance, network assumptions, and bridge integration risks

---

## 3. When to Use This Skill

**Prompt trigger**

```
Does the code use Clarity language (define-public, define-read-only, etc.)? ──yes──> Use this skill
│
no
│
v
Does the contract deploy on Stacks blockchain or reference STX/SIP tokens? ──yes──> Use this skill
│
no
│
v
Does the code use tx-sender, contract-caller, or as-contract? ──yes──> Use this skill
│
no
│
v
Does the contract implement SIP-009, SIP-010, or SIP-013 traits? ──yes──> Use this skill
│
no
│
v
Skip this skill
```

**Concrete triggers**

- `(define-public ...)` or `(define-read-only ...)` function definitions
- `tx-sender`, `contract-caller`, `as-contract` usage
- `(ft-transfer? ...)`, `(nft-transfer? ...)`, `(stx-transfer? ...)`
- `(impl-trait ...)` referencing SIP-009/010/013
- `(post-condition-mode ...)`, `(asserts! ...)`, `(unwrap-panic ...)`
- `(map-set ...)`, `(map-insert ...)`, `(map-get? ...)`
- `(contract-call? ...)` inter-contract invocations
- `(ft-mint? ...)`, `(nft-mint? ...)` minting logic
- `block-height`, `burn-block-height`, `stacks-block-height` references
- TypeScript SDK: `import ... from "@stacks/transactions"`, `makeContractCall`, `PostConditionMode.Allow`
- TypeScript SDK: `standardPrincipalCV`, `contractPrincipalCV`, `listCV`, `uintCV`
- TypeScript SDK: `callReadOnlyFunction`, `broadcastTransaction`, `makeContractDeploy`

## Additional resources

- For real-world TypeScript vulnerable patterns using `@stacks/transactions` SDK, see [typescript-vulnerable-patterns.md](references/typescript-vulnerable-patterns.md)

---

## Goal

Produce a `findings.md` file containing all identified vulnerabilities in the target Clarity contract(s), each with a title, code location, description, attack scenario, and fix recommendation. Every checkpoint in the checklist below must be evaluated. The audit is complete when all checkpoints have been checked and all findings are reported.

## Workflow

### Step 1: Establish scope
Identify the target Clarity contract files and modules to audit. Confirm the project uses Clarity on Stacks and matches this skill's domain.

**Artifacts**: list of target `.clar` files, confirmed project type
**Success criteria**: The target file set is known and confirmed to be Clarity contracts on Stacks.

### Step 2: Execute checklist
Evaluate each checkpoint (Section 4) against the target code. For each checkpoint, follow the Identify → Analyze → Exploitability → Check stages.

**Artifacts**: per-checkpoint notes (finding or "not applicable" with brief justification)
**Success criteria**: Every checkpoint has been evaluated.

### Step 3: Compile findings
Collect all identified issues into `findings.md` using the output format below.

**Artifacts**: `findings.md`
**Human checkpoint**: Present the draft findings to the user for review before writing the file.
**Success criteria**: The user has reviewed and approved the findings.

## Output Format

Each finding in `findings.md` must contain these five sections:

**Title**: `{Some Issue Or Flaw} Leads To {Some Outcome}` — capitalize every word except prepositions.

**Code location**: `filename-L{start}~L{end}` — placed above the description.

**Description**: Describe the function's purpose, identify the issue, and outline potential impacts. Use clear narrative; enclose functions or variables in backticks.

**Scenario**: Provide attack steps using fictional actors (Alice, Bob, etc.) as numbered steps.

**Recommendation**: Actionable fix suggestion.

## Rules

- Do not report a finding without a concrete code location.
- Do not skip a checkpoint — mark it "not applicable" with a brief justification if the pattern is absent.
- Pause for user confirmation before writing findings.md.
- If a checkpoint triggers a cross-reference to another skill, note it in the finding but do not execute the other skill.

---

## 4. Checklist

### Title: 0x0000-contract-caller-must-be-used-instead-of-tx-sender-for-authorization

Description
`tx-sender` represents the original transaction signer and persists across inter-contract calls. When Contract A calls Contract B, `tx-sender` inside B still refers to the original user — not Contract A. This allows intermediary contracts to inherit the user's identity and bypass authorization checks. `contract-caller` correctly identifies the immediate caller and should be used for authorization in any function callable by other contracts.

Identify
1. Find all `(asserts! ...)` and `(if ...)` guards that compare against `tx-sender`.
2. Locate public functions that could be invoked by other contracts via `(contract-call? ...)`.
3. Identify admin/owner checks that rely on `tx-sender` identity.

Analyze
1. For each `tx-sender` authorization check, determine whether the function is callable by intermediary contracts.
2. Verify whether an attacker-controlled contract could invoke the function while inheriting a victim's `tx-sender`.
3. Check if `contract-caller` would be the correct identity to compare against for the function's trust model.

Exploitability
1. Determine if a malicious intermediary contract can trick a user into calling it, then relay the call to the target contract with the user's `tx-sender` identity intact.
2. Assess whether the function protects high-value operations (transfers, admin actions) that an attacker would benefit from executing under a victim's identity.

Check
1. All authorization guards on public functions callable by other contracts must use `contract-caller` instead of `tx-sender`.
2. `tx-sender` should only be used for authorization in entry-point functions that are never called by other contracts, or where the original signer identity is explicitly required.
3. Document the intended trust model (direct-user-only vs contract-callable) for each public function.

---

### Title: 0x0001-as-contract-context-must-not-grant-unintended-principal-elevation

Description
`(as-contract ...)` temporarily switches `tx-sender` and `contract-caller` to the contract's own principal. This is used for the contract to perform actions on its own behalf (e.g., transferring tokens it holds). If `as-contract` is reachable via unintended code paths — particularly error-handling branches or user-controlled flow — an attacker can trigger operations with the contract's elevated identity. The Charisma exploit (Sep 2024, 183k STX) exploited exactly this pattern: an error path retained `as-contract` context, allowing unauthorized token transfers.

Identify
1. Find all `(as-contract ...)` blocks in the contract.
2. Locate the enclosing control flow: conditionals, `match`, `try!`, `unwrap!`, error branches.
3. Identify what operations execute inside the `as-contract` context.

Analyze
1. For each `as-contract` block, trace all code paths that reach it — including error/fallback branches.
2. Verify that the `as-contract` context is only entered after all authorization and validation checks have passed.
3. Check whether user-supplied inputs influence which operations execute within the `as-contract` scope.

Exploitability
1. Determine if an attacker can craft inputs that force execution into an `as-contract` block via an error or fallback path.
2. Assess whether the contract holds assets (STX, FTs, NFTs) that could be transferred using the elevated principal context.
3. Evaluate whether the `as-contract` block performs state changes that benefit an attacker when executed under the contract's identity.

Check
1. Every `as-contract` block must be guarded by completed authorization checks — no error path should enter `as-contract` without prior validation.
2. Minimize the scope of `as-contract` blocks to the narrowest necessary operation.
3. Ensure `as-contract` is never reachable through user-controllable branching (e.g., trait dispatch, parameter-dependent conditionals) without explicit access control.

---

### Title: 0x0002-owner-admin-checks-must-compare-against-stored-principal

Description
Authorization checks must compare `contract-caller` (or `tx-sender` where appropriate) against a principal stored in contract state — not against a hardcoded principal literal or a value derived from user input. Hardcoded principals prevent ownership transfer; user-derived comparisons are trivially bypassable.

Identify
1. Find all admin/owner authorization patterns: `(asserts! (is-eq contract-caller ...) ...)`.
2. Locate the storage of owner/admin principals: `(define-data-var ...)` or `(define-map ...)`.
3. Check for hardcoded principal literals in authorization comparisons.

Analyze
1. Verify admin checks compare against a stored `(var-get ...)` or `(map-get? ...)` value.
2. Check that the owner/admin principal can be updated through a secure transfer mechanism.
3. Ensure no authorization check compares against a function parameter or computed value that the caller controls.

Exploitability
1. Determine if an attacker can bypass admin checks by controlling the comparison target.
2. Assess whether hardcoded principals create a single point of failure if the key is compromised.
3. Evaluate whether the admin transfer function itself has proper access control.

Check
1. All admin/owner checks must compare against a `(var-get ...)` stored principal.
2. Owner transfer must implement a two-step pattern: `set-pending-owner` followed by `accept-ownership` by the new owner.
3. No authorization comparison should use hardcoded principal literals or caller-supplied parameters as the trusted identity.

---

### Title: 0x0003-ft-transfer-and-nft-transfer-must-enforce-sender-authorization

Description
`(ft-transfer? token amount sender recipient)` and `(nft-transfer? token id sender recipient)` accept an explicit `sender` parameter but do **not** automatically verify that the caller is authorized to transfer from that sender. Unlike `(stx-transfer? ...)` which requires `tx-sender` to equal the sender, `ft-transfer?` and `nft-transfer?` will execute for any caller-specified sender. If the contract does not validate that `contract-caller` or `tx-sender` equals the sender (or has approval), any caller can drain tokens from any address.

Identify
1. Find all `(ft-transfer? ...)` and `(nft-transfer? ...)` calls.
2. Check whether the `sender` parameter is a function argument or a fixed value.
3. Locate any preceding authorization check that validates the caller's right to transfer from the specified sender.

Analyze
1. For each transfer call, verify an explicit `(asserts! (is-eq tx-sender sender) ...)` or `(asserts! (is-eq contract-caller sender) ...)` guard exists before the transfer.
2. If an allowance/approval mechanism is implemented, verify it is checked and decremented atomically.
3. Check whether `sender` can be an arbitrary user-supplied principal without validation.

Exploitability
1. Determine if an attacker can call the transfer function with a victim's principal as `sender` and drain their tokens.
2. Assess the scope of impact: can all token holders be affected, or only specific accounts?
3. Evaluate whether the function is externally callable or restricted to internal use.

Check
1. Every public function containing `(ft-transfer? ...)` or `(nft-transfer? ...)` with a caller-supplied `sender` must have an explicit authorization check verifying the caller's right to transfer.
2. For SIP-010 `transfer` implementations, verify `(asserts! (is-eq tx-sender sender) ...)` is present.
3. Internal-only transfer helpers must not be exposed as public functions.

---

### Title: 0x0004-sip-trait-implementations-must-satisfy-standard-security-requirements

Description
SIP-009 (NFTs), SIP-010 (fungible tokens), and SIP-013 (semi-fungible tokens) define trait interfaces that wallets, marketplaces, and DeFi protocols rely on. Non-compliant implementations can break composability or introduce security gaps. Key requirements: SIP-010 `transfer` must verify `(is-eq tx-sender sender)`, must fire `print` events for post-condition detection, and `get-balance`/`get-total-supply` must return accurate values.

Identify
1. Find `(impl-trait ...)` declarations referencing SIP-009, SIP-010, or SIP-013 trait contracts.
2. Locate implementations of required trait functions: `transfer`, `get-balance`, `get-total-supply`, `get-owner`, `get-token-uri`, etc.
3. Check for `(print ...)` event emission in transfer functions.

Analyze
1. Verify SIP-010 `transfer` enforces `(is-eq tx-sender sender)` and optionally respects the `memo` parameter.
2. Verify `get-balance` and `get-total-supply` return values consistent with actual state.
3. Check SIP-009 `transfer` enforces sender is the current owner and emits appropriate events.
4. For SIP-013, verify `transfer` and `transfer-many` enforce sender authorization for each asset-id.

Exploitability
1. Determine if a non-compliant `transfer` allows unauthorized transfers exploitable by marketplaces or DeFi integrations.
2. Assess whether incorrect `get-balance` reporting can be used to inflate collateral or voting power in downstream protocols.
3. Evaluate whether missing `print` events prevent post-conditions from detecting transfers.

Check
1. SIP-010: `transfer` must check `(is-eq tx-sender sender)`, emit `(print ...)`, and correctly update balances.
2. SIP-009: `transfer` must verify sender ownership, emit events, and update `get-owner` consistently.
3. SIP-013: `transfer` and `transfer-many` must authorize per-asset sender identity.
4. All read-only query functions must return values consistent with the actual token state.

---

### Title: 0x0005-mint-functions-must-enforce-access-control-and-supply-caps

Description
Minting functions (`ft-mint?`, `nft-mint?`) create new tokens. Without access control, any caller can mint arbitrary amounts. Without supply caps, authorized minters can inflate supply beyond intended limits. Both represent critical value-extraction vectors.

Identify
1. Find all `(ft-mint? ...)` and `(nft-mint? ...)` calls.
2. Locate access control checks preceding mint operations.
3. Check for supply cap enforcement: `(var-get total-supply)` comparisons, `(ft-get-supply ...)` checks.

Analyze
1. Verify only authorized principals (contract owner, designated minter role) can trigger mint operations.
2. Check that supply caps are enforced before minting, not after.
3. Verify that the minter role itself has proper governance (can be updated, uses stored principal).

Exploitability
1. Determine if an unauthorized caller can trigger minting via public function access.
2. Assess whether supply caps can be bypassed through batch minting, re-entrancy-like patterns, or governance manipulation.
3. Evaluate the economic impact of unlimited minting on token value and protocol solvency.

Check
1. All mint functions must be guarded by `(asserts! (is-eq contract-caller (var-get minter)) ...)` or equivalent stored-principal check.
2. Supply caps must be checked before minting: `(asserts! (<= (+ current-supply amount) max-supply) ...)`.
3. The minter role must be updateable through a governed process with proper access control.

---

### Title: 0x0006-list-parameters-must-validate-element-uniqueness-to-prevent-duplication

Description
Clarity's `(list ...)` type does not enforce element uniqueness. When a function iterates over a list parameter to process items (e.g., collateral assets, reward claims, vote targets), duplicate entries cause the same item to be processed multiple times. The Zest Protocol exploit (Apr 2024, 322k STX) used duplicate list entries to inflate collateral value by processing the same asset multiple times.

Identify
1. Find public functions that accept `(list ...)` parameters.
2. Locate iteration patterns: `(fold ...)`, `(map ...)`, `(filter ...)` over the list parameter.
3. Identify what state changes or value accumulation occurs per list element.

Analyze
1. Determine whether duplicate elements in the list cause repeated state changes or value accumulation.
2. Check if the function validates uniqueness before processing (e.g., tracking seen elements in a map).
3. Assess whether the iterated operation is idempotent — duplicates harmless — or cumulative — duplicates exploitable.

Exploitability
1. Determine if an attacker can submit a list with duplicate entries to inflate a calculated value (collateral, rewards, votes).
2. Assess the economic impact: can duplicates cause direct fund extraction or only governance manipulation?
3. Evaluate whether off-chain validation or post-conditions can mitigate the risk.

Check
1. Functions processing list parameters for cumulative effects must validate element uniqueness before iteration.
2. Use a fold-based deduplication check or maintain a tracking map to reject duplicates.
3. For fixed-set operations (e.g., known collateral types), validate list elements against an approved set rather than accepting arbitrary values.

---

### Title: 0x0007-trait-reference-parameters-must-be-validated-against-approved-contracts

Description
Clarity allows passing trait references as function parameters, enabling callers to specify which contract implementation to use. Without validation, an attacker can pass a malicious contract that implements the trait interface but executes adversarial logic — stealing funds, manipulating state, or returning false data. This is analogous to the EVM pattern of passing arbitrary contract addresses but with Clarity's trait system.

Identify
1. Find public functions that accept trait reference parameters: `(token <ft-trait>)`, `(nft <nft-trait>)`, etc.
2. Locate how the trait reference is used within the function: calls to trait functions, token operations.
3. Check for validation of the trait reference against an approved contract list.

Analyze
1. Verify the contract validates trait references against a stored whitelist before use.
2. Check whether a malicious trait implementation could return manipulated values from read-only functions.
3. Assess whether the trait reference is used for token transfers that could redirect funds.

Exploitability
1. Determine if an attacker can pass a malicious contract that implements the trait but drains funds or returns false balances.
2. Assess whether price oracle or balance queries through the trait can be manipulated.
3. Evaluate the blast radius: does the malicious trait affect only the caller or all protocol users?

Check
1. All trait reference parameters must be validated against a stored whitelist: `(asserts! (is-eq (contract-of token) (var-get approved-token)) ...)`.
2. For multi-token protocols, maintain a map of approved trait contracts and verify membership before any operation.
3. Never trust return values from unvalidated trait references for security-critical decisions (pricing, balances, ownership).

---

### Title: 0x0008-unwrap-panic-must-not-create-denial-of-service-vectors

Description
`(unwrap-panic ...)` aborts the entire transaction if the value is `none` or `(err ...)`. In functions processing multiple items or user-supplied data, a single `none` or error triggers a full transaction revert. Attackers can exploit this by crafting inputs that cause panics, blocking legitimate operations. Unlike `(unwrap! ...)` which allows graceful error returns, `unwrap-panic` provides no recovery path.

Identify
1. Find all `(unwrap-panic ...)` calls in public functions.
2. Determine the source of the unwrapped value: user input, map lookups, external contract calls.
3. Locate functions that process batches or lists where a single panic aborts the entire batch.

Analyze
1. For each `unwrap-panic`, assess whether the unwrapped value can be `none`/`err` due to user-controlled input or external state.
2. Check if the panic is in a critical path that other users depend on (e.g., reward distribution, batch processing).
3. Verify whether `(unwrap! ...)` with a meaningful error code would be a safer alternative.

Exploitability
1. Determine if an attacker can craft inputs that trigger `unwrap-panic` to block legitimate operations.
2. Assess whether the DoS affects a single user's transaction or protocol-wide operations (e.g., epoch transitions, reward distributions).
3. Evaluate the cost-to-impact ratio: how cheaply can an attacker trigger persistent DoS?

Check
1. Public functions must not use `unwrap-panic` on values derived from user input or external state.
2. Replace `(unwrap-panic ...)` with `(unwrap! ... (err error-code))` to allow graceful failure.
3. Batch-processing functions must use `(match ...)` or `(unwrap! ...)` to skip invalid entries rather than aborting the entire batch.

---

### Title: 0x0009-optional-returns-must-handle-none-case-explicitly

Description
`(map-get? ...)`, `(get ...)` on optionals, and contract calls returning `(optional ...)` can yield `none`. If `none` is not handled, subsequent operations may silently use default values (for arithmetic: 0) or panic. Both outcomes can be exploitable: zero-value defaults can bypass payment checks; panics can cause DoS.

Identify
1. Find all `(map-get? ...)` calls and trace how their return value is consumed.
2. Locate `(default-to ...)` usage and verify the default value is safe.
3. Check for `(get ...)` on optional tuple fields without `none` handling.

Analyze
1. Verify `none` cases are explicitly handled with `(match ...)`, `(unwrap! ...)`, or safe `(default-to ...)` values.
2. Check if `(default-to 0 ...)` or `(default-to u0 ...)` can bypass intended payment or balance checks.
3. Assess whether unhandled `none` propagates into arithmetic, comparisons, or transfer amounts.

Exploitability
1. Determine if an attacker can trigger a `none` return to bypass a payment or balance requirement via default-to-zero.
2. Assess whether `none` propagation can cause incorrect state updates (e.g., setting a balance to zero).
3. Evaluate whether the unhandled case silently succeeds or visibly fails.

Check
1. All `(map-get? ...)` results used in security-critical logic must use `(match ...)` or `(unwrap! ...)` — not bare `(default-to ...)`.
2. When `(default-to ...)` is used, verify the default value cannot bypass security checks.
3. Functions returning `(optional ...)` types must document the `none` semantics for callers.

---

### Title: 0x000a-post-conditions-must-use-deny-mode-and-cover-all-asset-transfers

Description
Stacks post-conditions are transaction-level assertions that constrain asset transfers. In `allow` mode, unlisted transfers proceed silently. In `deny` mode, any transfer not covered by a post-condition causes the transaction to abort. Using `allow` mode or incomplete `deny` coverage allows contracts to perform hidden transfers. Wallets and users rely on post-conditions as a safety net, but they only protect against unexpected **asset transfers** — not state changes.

Identify
1. Locate transaction construction and post-condition specification (typically in deployment scripts, client code, or SDK usage).
2. Identify all asset transfers within the contract: `(stx-transfer? ...)`, `(ft-transfer? ...)`, `(nft-transfer? ...)`.
3. Check whether the contract documentation or SDK recommends `allow` or `deny` mode.

Analyze
1. Verify `deny` mode is recommended/enforced for all user-facing transactions.
2. Check that post-conditions cover every asset transfer path in the contract, including error-path transfers.
3. Assess whether `as-contract` transfers are covered by post-conditions (they reference the contract principal, not the user).

Exploitability
1. Determine if `allow` mode permits a malicious contract to execute hidden transfers not visible to the user.
2. Assess whether incomplete `deny` coverage leaves specific transfer paths unprotected.
3. Evaluate whether `as-contract` transfers can bypass user-specified post-conditions.

Check
1. All user-facing transaction documentation must recommend `deny` mode post-conditions.
2. Post-conditions must cover every `stx-transfer?`, `ft-transfer?`, and `nft-transfer?` path in the contract.
3. Document which transfers occur under `as-contract` context (different principal) so wallets can set correct post-conditions.

---

### Title: 0x000b-state-changes-invisible-to-post-conditions-must-have-contract-level-guards

Description
Post-conditions only constrain asset transfers (STX, FTs, NFTs). They cannot detect or prevent: map/variable state changes, data-var updates, NFT metadata modifications, or changes to contract configuration. This creates a blind spot exploitable by malicious contracts — particularly commission/callback contracts in NFT marketplaces that modify state (e.g., update prices, change ownership flags) in ways invisible to post-conditions.

Identify
1. Find contract interactions that invoke external contracts (e.g., commission contracts, callback handlers, plugin contracts).
2. Locate state changes in those external contracts: `(map-set ...)`, `(var-set ...)`, `(map-delete ...)`.
3. Identify user-facing operations that rely solely on post-conditions for safety without contract-level guards.

Analyze
1. Verify that security-critical state changes have contract-level guards independent of post-conditions.
2. Check whether external contract callbacks can modify state that affects the calling contract's security assumptions.
3. Assess whether the "honey-pot" pattern applies: state changes that make future operations profitable for the attacker but invisible to the victim's post-conditions.

Exploitability
1. Determine if a malicious commission/callback contract can modify prices, ownership, or permissions in ways hidden from post-conditions.
2. Assess whether the state change creates an immediate exploit or a time-delayed trap.
3. Evaluate whether the victim has any way to detect the malicious state change before it is exploited.

Check
1. All security-critical state changes must be guarded by contract-level authorization checks — never rely solely on post-conditions.
2. External contract callbacks must be constrained: validate the callback contract against a whitelist, or limit what state the callback can modify.
3. Audit commission and plugin contracts for state modifications beyond their intended scope.

---

### Title: 0x000c-map-set-vs-map-insert-semantics-must-match-intended-behavior

Description
`(map-set ...)` overwrites existing entries unconditionally. `(map-insert ...)` only writes if the key does not already exist, returning `false` if the key is present. Using `map-set` where `map-insert` is intended allows overwriting existing data (e.g., replacing a bid, overwriting a registration). Using `map-insert` where `map-set` is intended causes silent update failures.

Identify
1. Find all `(map-set ...)` and `(map-insert ...)` calls.
2. Determine the intended semantics: should the operation create-only, update-only, or upsert?
3. Check whether the return value of `(map-insert ...)` (bool) is checked.

Analyze
1. For each `(map-set ...)`, verify that unconditional overwrite is the correct behavior — not accidental data replacement.
2. For each `(map-insert ...)`, verify the `false` return (key already exists) is handled, not silently ignored.
3. Check for patterns where `map-set` is used for registration/initialization that should be create-only.

Exploitability
1. Determine if an attacker can overwrite another user's data via `map-set` where `map-insert` was intended (e.g., replacing a bid, claiming a registration).
2. Assess whether silently failed `map-insert` operations leave the contract in an inconsistent state.
3. Evaluate whether the overwrite can steal funds, alter permissions, or corrupt protocol state.

Check
1. Initialization and registration operations must use `(map-insert ...)` and check the return value.
2. Update operations must use `(map-set ...)` with preceding existence verification where needed.
3. The return value of `(map-insert ...)` must never be silently discarded — use `(asserts! (map-insert ...) (err ...))` for critical operations.

---

### Title: 0x000d-inter-contract-calls-must-handle-errors-and-validate-return-values

Description
`(contract-call? ...)` returns a `(response ...)` type. If the called contract returns an error and the caller does not handle it, the error propagates up and may abort the entire transaction or leave partial state updates. Additionally, the caller must not blindly trust return values from external contracts — a malicious or buggy contract can return manipulated data.

Identify
1. Find all `(contract-call? ...)` invocations.
2. Check how the response is handled: `(try! ...)`, `(unwrap! ...)`, `(match ...)`, or ignored.
3. Identify whether return values from external calls are used for security-critical decisions.

Analyze
1. Verify all `contract-call?` responses are explicitly handled — no `(unwrap-panic ...)` on external call results.
2. Check whether error propagation from external calls can leave the calling contract in an inconsistent state (partial state updates before the failing call).
3. Assess whether return values from external contracts are trusted for pricing, balance, or authorization decisions.

Exploitability
1. Determine if a malicious external contract can force transaction aborts by returning errors, causing DoS.
2. Assess whether partial state updates before a failed external call create exploitable inconsistencies.
3. Evaluate whether manipulated return values from external calls can influence security-critical logic.

Check
1. All `(contract-call? ...)` results must be handled with `(try! ...)`, `(unwrap! ...)`, or `(match ...)` — never `(unwrap-panic ...)`.
2. State changes before external calls must be rolled back or safe to retain if the external call fails.
3. Return values from untrusted external contracts must not be used for security-critical decisions without independent validation.

---

### Title: 0x000e-admin-functions-must-enforce-access-control-and-migration-paths

Description
Clarity contracts deployed on Stacks are immutable — there is no proxy/upgrade pattern like in EVM. All admin functionality must be built into the contract at deployment. This makes governance design critical: overly permissive admin functions are permanently exploitable; missing admin functions are permanently absent. Migration to new contract versions requires explicit asset-migration logic.

Identify
1. Find all functions that modify protocol parameters, pause operations, or transfer administrative control.
2. Locate access control on these functions: `(asserts! (is-eq contract-caller ...) ...)`.
3. Check for emergency mechanisms: pause, shutdown, asset migration to new contract.

Analyze
1. Verify all admin functions have proper access control using stored principals (see checkpoint 0x0002).
2. Check whether admin capabilities are appropriately scoped — no single function should allow unrestricted parameter changes.
3. Assess whether the contract includes migration paths for moving assets/state to a successor contract.

Exploitability
1. Determine if missing admin functions prevent the protocol from responding to discovered vulnerabilities.
2. Assess whether overly powerful admin functions allow a compromised admin key to drain all funds.
3. Evaluate whether the lack of upgrade paths means discovered vulnerabilities are permanently exploitable.

Check
1. All admin functions must enforce access control and follow the principle of least privilege.
2. Critical admin operations (parameter changes, pause/unpause) should emit events via `(print ...)` for transparency.
3. Contracts holding user funds should include governed migration/withdrawal paths to successor contracts.
4. Consider timelock patterns for sensitive admin operations (implement via block-height delay checks).

---

### Title: 0x000f-contract-must-not-assume-block-timing-or-finality-guarantees

Description
The Stacks blockchain has variable block times and its finality model depends on Bitcoin anchor blocks. `block-height` (Stacks blocks) and `burn-block-height` (Bitcoin blocks) advance at different rates. After the Nakamoto upgrade, Stacks block production is faster (~5 seconds) but finality still depends on Bitcoin. Contracts that assume fixed block intervals for time-sensitive operations (auctions, vesting, oracle freshness) may behave unpredictably.

Identify
1. Find all references to `block-height`, `burn-block-height`, and `stacks-block-height`.
2. Locate time-dependent logic: deadlines, cooldowns, vesting schedules, oracle staleness checks.
3. Check for hardcoded block-interval assumptions (e.g., `(+ block-height u144)` assuming "~1 day").

Analyze
1. Verify time-critical logic accounts for variable block production rates.
2. Check whether `block-height` vs `burn-block-height` is chosen appropriately for the use case (Stacks speed vs Bitcoin finality).
3. Assess whether the Nakamoto upgrade's changed block timing invalidates existing assumptions.

Exploitability
1. Determine if variable block timing allows manipulation of time-dependent logic (e.g., bidding past a deadline, early vesting claims).
2. Assess whether block-height-based oracle staleness checks can be stale in real time but appear fresh in block time.
3. Evaluate whether finality assumptions (treating Stacks blocks as final before Bitcoin confirmation) create double-spend or reorg risks.

Check
1. Time-sensitive operations must use `burn-block-height` for finality-dependent logic and document the chosen block-height type.
2. Avoid hardcoded block-interval constants for real-time durations — document assumptions and use conservative bounds.
3. Oracle freshness checks must account for the difference between block time and wall-clock time.

---

### Title: 0x0010-cross-chain-principal-encoding-must-be-validated-in-bridge-integrations

Description
Bridge contracts that move assets between Stacks and other chains must validate principal encoding, proof formats, and cross-chain message authenticity. Stacks principals have a unique format (standard principals and contract principals) that differs from EVM addresses. Incorrect encoding, missing validation of cross-chain proofs, or trusting unvalidated bridge relayer messages can lead to unauthorized minting on the destination chain or theft of locked assets on the source chain.

Identify
1. Find bridge-related contract logic: lock/mint, burn/release patterns.
2. Locate cross-chain message handling: proof verification, relayer message parsing, principal encoding/decoding.
3. Check for trait-based bridge interfaces and how bridge operator roles are authorized.

Analyze
1. Verify cross-chain proof validation is cryptographically sound and not bypassable.
2. Check principal encoding/decoding for format mismatches between Stacks principals and external chain addresses.
3. Assess whether bridge operator/relayer roles are properly governed and whether a compromised relayer can mint arbitrary tokens.

Exploitability
1. Determine if principal encoding mismatches allow minting to unintended recipients or claiming from wrong source addresses.
2. Assess whether forged or replayed cross-chain proofs can trigger unauthorized minting or releasing.
3. Evaluate whether bridge operator compromise can drain locked assets or inflate supply on the destination chain.

Check
1. Principal encoding between Stacks and external chains must be explicitly validated with format checks.
2. Cross-chain proofs must be verified against trusted anchor state (Bitcoin block headers for Stacks-Bitcoin bridges).
3. Bridge operator roles must use multi-sig or threshold signatures with proper governance.
4. Implement rate limits and supply caps on bridge mint/release operations as defense-in-depth.
