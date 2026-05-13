---
name: audit-ln-dapp-general
description: Audits Lightning Network dApp implementations for preimage exposure, timelock misconfiguration, HTLC state machine flaws, swap non-atomicity, force-close fee budget gaps, replacement cycling vulnerabilities, and client-side key safety. Produces a findings.md report with ranked vulnerabilities.
when_to_use: |
  Use when user mentions "Lightning Network dApp", "LN swap", "submarine swap", "reverse swap", "Boltz", "Loop", "LSP", "liquidity service provider", "LN payment processor", "HTLC", "preimage", "payment hash", "CLTV expiry", "timelock delta", "channel force-close", "watchtower", "LN bridge", "Lightning marketplace", "PTLC", "adaptor signature", "Taproot channel", "bolt11", "ln-service", "lnrpc", "@boltz/boltz-core", "lnurl-pay", "createInvoice", "payViaPaymentRequest", "subscribeToForwards", "getChannels" or asks about Lightning Network application security, swap atomicity, HTLC lifecycle, or LN integration best practices.
  Do NOT use for core Lightning node internals (LND/CLN/LDK source code) or on-chain-only Bitcoin applications.
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

# Lightning Network dApp Vulnerability Scanner

## 1. Introduction

Lightning Network dApps — swap services (Boltz, Loop), payment processors (BTCPay, LNbits), LSPs (Liquidity Service Providers), bridges, and LN-enabled marketplaces — build on top of the HTLC-based payment layer to deliver fast, low-cost Bitcoin transactions. Unlike core node implementations (LND, CLN, LDK internals), these applications manage the business logic around preimage handling, timelock coordination, channel lifecycle, and on-chain settlement. Security failures at this layer have led to real-world fund losses including CVE-2020-26896 (premature preimage revelation enabling free option attacks), replacement cycling attacks demonstrated against LN forwarding nodes in 2023, and submarine swap non-atomicity bugs allowing double-claims.

The LN dApp attack surface spans six critical domains: preimage safety (the atomic primitive linking payment legs), timelock engineering (safety budgets across L1/L2 boundaries), HTLC state machine correctness (commitment binding and settlement guarantees), swap protocol atomicity (hashlock and timelock coordination for submarine/reverse swaps), mempool and fee resilience (force-close fee budgets, replacement cycling), and channel state management (watchtower reliance, revocation secret durability). Client-side security and forward-looking Taproot/PTLC concerns complete the picture.

This skill covers LN-based applications and integrations, NOT core Lightning node internals. It targets auditors reviewing swap services, payment processors, LSPs, bridges, LN-enabled marketplaces, and any system that constructs, forwards, or settles HTLC-based payments or coordinates on-chain/off-chain atomic operations. All pseudocode uses Bitcoin Script semantics, BOLT specification references, and Lightning channel operation primitives. For PSBT-specific construction and signing vulnerabilities in the on-chain leg, cross-reference the `audit-psbt-security` skill.

---

## 2. Purpose

This skill audits Lightning Network dApp implementations to detect preimage exposure, timelock misconfiguration, HTLC state machine flaws, submarine and reverse swap non-atomicity, force-close fee budget gaps, replacement cycling vulnerabilities, insufficient confirmation depth, watchtower reliance failures, revocation secret mismanagement, client-side key exfiltration risks, and Taproot channel or PTLC adaptor signature weaknesses.

---

## 3. When to Use This Skill

**Prompt trigger**

```
Does the code handle Lightning Network payments (invoices, HTLCs, preimages)? ──yes──> Use this skill
│
no
│
v
Does it implement submarine swaps, reverse swaps, or Loop-style rebalancing? ──yes──> Use this skill
│
no
│
v
Does it manage Lightning channel state (commitments, force-close, penalties)? ──yes──> Use this skill
│
no
│
v
Does it coordinate timelocks between on-chain HTLCs and Lightning payments? ──yes──> Use this skill
│
no
│
v
Does it operate as an LSP, payment processor, or LN-enabled marketplace? ──yes──> Use this skill
│
no
│
v
Does it implement Taproot channels or PTLC-based payment protocols? ──yes──> Use this skill
│
no
│
v
Skip this skill
```

**Concrete triggers**

- Preimage generation, storage, or revelation (`preimage`, `payment_hash`, `SHA256`, `settle_invoice`, `reveal_preimage`)
- HTLC construction and forwarding (`UpdateAddHtlc`, `UpdateFulfillHtlc`, `UpdateFailHtlc`, `commitment_signed`, `revoke_and_ack`)
- Timelock handling (`cltv_expiry`, `cltv_expiry_delta`, `to_self_delay`, `OP_CHECKLOCKTIMEVERIFY`, `OP_CHECKSEQUENCEVERIFY`)
- Swap protocol operations (`submarine_swap`, `reverse_swap`, `loop_in`, `loop_out`, `on_chain_htlc`, `claim_tx`, `refund_tx`)
- Invoice and payment lifecycle (`create_invoice`, `pay_invoice`, `payment_secret`, `payment_state`, `ACCEPTED`, `SETTLED`, `CANCELLED`)
- Channel management (`open_channel`, `close_channel`, `force_close`, `breach_remedy`, `commitment_tx`, `penalty_tx`)
- Watchtower integration (`watchtower`, `breach_detection`, `penalty_broadcast`, `justice_tx`)
- Fee management (`anchor_output`, `cpfp`, `fee_bump`, `fee_reserve`, `force_close_fee`)
- Confirmation depth checks (`confirmations`, `block_depth`, `reorg_safe`, `settlement_final`)
- Client-side key handling (`wallet_key`, `node_key`, `channel_key`, `preimage_storage`, `encrypted_backup`)
- Taproot/PTLC operations (`taproot_channel`, `ptlc`, `adaptor_signature`, `point_lock`, `key_path`, `script_path`)
- TypeScript/Node.js LN SDK usage (`bolt11.decode`, `ln-service`, `lnrpc`, `createInvoice`, `payViaPaymentRequest`, `subscribeToForwards`, `getChannels`, `closeChannel`, `@boltz/boltz-core`, `constructClaimTransaction`, `constructRefundTransaction`, `lnurl-pay`, `crypto.randomBytes`)

**Additional resources**

- [TypeScript Vulnerable Patterns Reference](references/typescript-vulnerable-patterns.md) — 17 real-world TypeScript anti-patterns mapped 1-to-1 with the checklist below (one per checkpoint). Use when auditing `bolt11`, `ln-service`, `@boltz/boltz-core`, or any Node.js Lightning integration.

---

## Goal

Produce a `findings.md` file containing all identified vulnerabilities in the target Lightning Network dApp implementation, each with a title, code location, description, attack scenario, and fix recommendation. Every checkpoint in the checklist below must be evaluated. The audit is complete when all checkpoints have been checked and all findings are reported.

## Workflow

### Step 1: Establish scope
Identify the target files and modules that handle LN payments, HTLCs, swaps, channel management, preimage handling, or fee management. Confirm the project is an LN dApp (not core node internals) and matches this skill's domain.

**Artifacts**: list of target files, confirmed project type
**Success criteria**: The target file set is known and confirmed to involve LN dApp logic.

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
- For PSBT-specific construction and signing vulnerabilities in the on-chain leg, note the cross-reference to `audit-psbt-security` but do not execute it.

---

## 4. Checklist

### Title: 0x0000-preimage-must-not-be-revealed-before-incoming-htlc-is-irrevocably-committed

Description
The preimage is the atomic link between payment legs in Lightning and swap protocols. Revealing the preimage before the incoming HTLC (or on-chain HTLC in a swap) is irrevocably committed grants the payer a "free option" — they learn proof of payment without the receiver being guaranteed funds. This is the mechanism behind CVE-2020-26896 and analogous free option attacks in swap services.

Identify

1. Locate preimage revelation points — search for `settle_invoice`, `fulfill_htlc`, `reveal_preimage`, or any code path where the preimage is returned to the payment sender or made visible on a public channel.
2. Find the incoming HTLC commitment verification — search for confirmation depth checks, `commitment_signed` acknowledgment, or on-chain HTLC confirmation logic that precedes preimage revelation.
3. Trace the preimage flow in swap protocols — identify where the swap service learns the preimage and when it reveals it to the counterparty (on-chain claim or LN settlement).

Analyze

1. Verify that preimage revelation is gated on irrevocable commitment of the incoming payment — for LN HTLCs, this means the incoming `commitment_signed` has been received AND the prior state has been revoked (via `revoke_and_ack`); for on-chain HTLCs, this means sufficient confirmation depth.
2. Check that the dApp does not reveal the preimage optimistically (e.g., settling the LN invoice before the on-chain funding transaction has confirmations in a submarine swap).
3. Verify that error or timeout paths do not leak the preimage — a failed settlement attempt that returns the preimage in an error message or log still constitutes revelation.

Exploitability

1. In a submarine swap, the service reveals the preimage (settles the LN invoice) before the on-chain HTLC has sufficient confirmations. The user learns the preimage, claims the on-chain HTLC, and if the funding transaction is reorged out, the service loses both the LN payment value and the on-chain funds.
2. In HTLC forwarding, revealing the preimage downstream before the incoming HTLC commitment is locked allows the upstream sender to cancel the incoming HTLC while the downstream preimage is already exposed — the forwarder loses the HTLC value.

Check

1. Gate preimage revelation on irrevocable commitment: require `revoke_and_ack` for LN HTLCs or minimum confirmation depth (3+ blocks) for on-chain HTLCs before any preimage exposure.
2. Ensure no code path (including error handlers, logs, and debug endpoints) leaks the preimage before the commitment gate is satisfied.
3. Add tests that attempt to extract the preimage before the incoming HTLC is committed and verify the system refuses to reveal it.

---

### Title: 0x0001-preimage-generation-must-use-csprng-and-prohibit-reuse-across-operations

Description
The preimage (typically 32 bytes) must be generated from a cryptographically secure pseudorandom number generator (CSPRNG). Weak randomness makes the preimage guessable, allowing an attacker to claim HTLCs without authorization. Reusing a preimage across multiple invoices or swap operations breaks atomicity isolation — settling one operation reveals the preimage for all operations sharing the same hash.

Identify

1. Locate preimage generation code — search for random byte generation (`crypto.randomBytes`, `os.urandom`, `getrandom`, `CSPRNG`) and trace how preimages are created for invoices and swap operations.
2. Search for preimage caching or reuse — find whether preimages are stored in a pool, derived deterministically from a seed, or reused across multiple payment hashes.
3. Check for deterministic preimage derivation that uses weak or predictable inputs (timestamps, counters, transaction IDs).

Analyze

1. Verify that preimage generation uses a CSPRNG (not `Math.random()`, not `rand()`, not timestamp-derived, not sequential).
2. Check that each invoice or swap operation generates a unique preimage — no two operations should share the same `payment_hash`.
3. Verify that preimage entropy is the full 256 bits (32 bytes) and is not truncated or reduced.

Exploitability

1. If the preimage is generated from `Math.random()` (48 bits of entropy on most platforms), an attacker can brute-force the preimage space and claim HTLCs locked to the resulting hash.
2. If the same preimage is reused across a submarine swap and a separate LN invoice, settling the invoice reveals the preimage that can be used to claim the on-chain HTLC, breaking swap atomicity.
3. Deterministic derivation from predictable inputs (e.g., `SHA256(user_id || counter)`) allows an attacker who knows the pattern to precompute preimages.

Check

1. Use a CSPRNG for all preimage generation — verify the entropy source is `/dev/urandom`, `crypto.getRandomValues()`, or platform-equivalent.
2. Enforce preimage uniqueness: never reuse a preimage across operations; generate a fresh 32-byte random value for each invoice or swap.
3. Add tests that generate a large batch of preimages and verify no duplicates or patterns exist.

---

### Title: 0x0002-payment-secret-must-be-verified-before-htlc-acceptance-to-prevent-hashlock-reuse-attacks

Description
The `payment_secret` (BOLT #11, 32-byte random value included in the invoice) prevents probing attacks and multi-path payment (MPP) confusion. Without verifying the payment secret, an intermediate node that knows the `payment_hash` (from a previous payment or separate channel) can construct a fake HTLC that the receiver settles, revealing the preimage to the wrong party. This enables hashlock reuse attacks and payment correlation.

Identify

1. Locate HTLC acceptance logic — search for `UpdateAddHtlc` processing, invoice lookup, and the point where the node decides to settle an incoming HTLC.
2. Find `payment_secret` verification — determine whether the node checks the `payment_secret` in the onion payload against the invoice's stored `payment_secret` before settling.
3. Search for legacy invoice handling that may not include `payment_secret` (pre-TLV invoices).

Analyze

1. Verify that the receiving node rejects any HTLC where the `payment_secret` does not match the invoice — this must be checked BEFORE revealing the preimage.
2. Check that MPP (multi-path payment) reconstruction validates the `payment_secret` on every partial payment and does not settle until all parts with the correct secret arrive.
3. Verify that the node does not accept HTLCs for unknown `payment_hash` values (keysend/spontaneous payments should have separate handling with appropriate security).

Exploitability

1. A probing attacker sends a small HTLC with a known `payment_hash` (from a previous invoice or observed on the network). Without `payment_secret` verification, the receiver settles and reveals the preimage — the attacker now has proof-of-payment for an invoice they did not pay.
2. In MPP, an attacker sends one legitimate partial payment and one forged partial with the correct hash but wrong secret. If the receiver settles without checking, the attacker learns the preimage from the legitimate path.

Check

1. Verify `payment_secret` before settling any HTLC — reject the HTLC if the secret does not match the invoice.
2. Require `payment_secret` on all invoices (BOLT #11 feature bit 14/15) and reject invoices without it.
3. Add tests that send HTLCs with correct `payment_hash` but incorrect `payment_secret` and verify the receiver fails the HTLC without revealing the preimage.

---

### Title: 0x0003-cltv-expiry-delta-must-account-for-safety-budget-including-fee-spikes-and-confirmation-delays

Description
The `cltv_expiry_delta` is the time budget each forwarding hop has to enforce an HTLC timeout on-chain if the downstream hop fails. If this delta is too small, the downstream HTLC may still be in-flight when the upstream HTLC expires, leaving the forwarder stuck — they cannot claim the timeout upstream (expired) and cannot claim the payment downstream (not yet settled). The safety budget must account for block variance, fee spikes, propagation delays, confirmation requirements, and potential chain congestion.

Identify

1. Locate `cltv_expiry_delta` configuration — search for channel parameters, routing configuration, and BOLT #2 `open_channel`/`accept_channel` fields.
2. Find HTLC timeout enforcement logic — search for HTLC-timeout transaction construction and the on-chain claim path used when a downstream HTLC fails.
3. Search for fee estimation integration — determine whether the timeout enforcement accounts for current mempool fee rates.

Analyze

1. Verify that `cltv_expiry_delta` is at least the minimum safety budget: `B_var + B_fee + B_prop + B_mon + B_conf` (see `timelock-safety-budget.md` reference). For mainnet, this should be >= 34 blocks (BOLT #2 recommendation) and ideally >= 72 blocks for adversarial conditions.
2. Check that the safety budget accounts for worst-case fee conditions — during high-congestion periods, the HTLC-timeout transaction may require many blocks to confirm.
3. Verify that the dApp does not allow users or configuration to set `cltv_expiry_delta` below the minimum safe threshold.

Exploitability

1. With a `cltv_expiry_delta` of 10 blocks, a fee spike that delays confirmation by 12 blocks means the forwarder cannot enforce the HTLC timeout before the upstream HTLC expires — the forwarder loses the HTLC value.
2. An attacker can deliberately congest the mempool (or exploit natural congestion) to delay the victim's timeout transaction, exploiting the insufficient safety margin.
3. In a swap service, an insufficient delta between the on-chain refund timeout and the LN payment timeout allows race conditions where both legs can be claimed.

Check

1. Enforce a minimum `cltv_expiry_delta` of at least 34 blocks (BOLT #2) and recommend 72+ blocks for swap protocols with on-chain legs.
2. Integrate fee estimation into timeout enforcement — ensure the HTLC-timeout transaction has a fee rate sufficient for timely confirmation.
3. Add tests that simulate fee spikes and delayed confirmations, verifying the safety budget prevents HTLC value loss.

---

### Title: 0x0004-timelock-values-must-not-cross-the-500-million-block-height-timestamp-boundary

Description
Bitcoin's `OP_CHECKLOCKTIMEVERIFY` (CLTV) interprets values below 500,000,000 as block heights and values >= 500,000,000 as Unix timestamps. The transaction's `nLockTime` must be in the same domain as the CLTV value. If a dApp's arithmetic causes a CLTV value to cross this boundary (e.g., overflow from block height into timestamp range), the script becomes either permanently unsatisfiable (funds locked forever) or trivially satisfiable (immediate claim). Lightning Network exclusively uses block heights for CLTV — any timestamp-domain value is a critical bug.

Identify

1. Locate all CLTV value computations — search for `cltv_expiry`, `nLockTime`, `OP_CHECKLOCKTIMEVERIFY`, and any arithmetic that produces timelock values.
2. Find the data types used for timelock arithmetic — check for integer overflow potential (32-bit unsigned, 64-bit signed, etc.).
3. Search for any code path that uses Unix timestamps for CLTV values in an LN context.

Analyze

1. Verify that all CLTV values in the LN dApp are block heights (< 500,000,000) and that no code path produces timestamp-domain values.
2. Check that arithmetic operations (`current_height + delta`) cannot overflow into the timestamp domain — at current block heights (~850,000) this requires a delta > 499,150,000, which is unrealistic but should still be validated.
3. Verify that `nLockTime` on HTLC-timeout and refund transactions is set to a block height consistent with the CLTV value.

Exploitability

1. A CLTV value that overflows into the timestamp domain (>= 500M) while `nLockTime` is a block height makes the script permanently unsatisfiable — funds are locked forever with no recovery path.
2. A CLTV value in the timestamp domain that corresponds to a past Unix timestamp is immediately satisfiable — the attacker can claim the HTLC without waiting for the intended timeout.
3. Type confusion between block heights and timestamps in swap protocol code can create a refund timeout that expires immediately, allowing the sender to double-claim.

Check

1. Assert that all CLTV values are < 500,000,000 and are block heights. Reject any timestamp-domain value in LN timelock code.
2. Validate arithmetic bounds: `current_height + delta < 500,000,000` for all timelock computations.
3. Add tests that attempt to set CLTV values at and above the 500M boundary and verify the system rejects them.

---

### Title: 0x0005-htlc-state-transitions-must-bind-to-commitment-updates-with-no-orphaned-states

Description
Each HTLC in a Lightning channel exists within the commitment transaction state machine. HTLC state transitions (add, fulfill, fail) must be atomically bound to commitment updates (`commitment_signed` + `revoke_and_ack`). If the dApp allows HTLC state changes that are not reflected in the latest commitment transaction, orphaned states can emerge — HTLCs that are logically settled but not committed, or committed but not reflected in the application state. These orphaned states can cause fund loss, double-settlement, or irrecoverable channel states.

Identify

1. Locate the HTLC state machine — search for HTLC lifecycle management (`OFFERED`, `ACCEPTED`, `FULFILLED`, `FAILED`, `COMMITTED`) and the transitions between states.
2. Find the commitment update logic — search for `commitment_signed` processing, `revoke_and_ack` handling, and the point where HTLC state changes are reflected in the new commitment transaction.
3. Search for race conditions between HTLC state changes and commitment updates — concurrent processing, async handlers, or database writes that can interleave.

Analyze

1. Verify that every HTLC state transition (add, fulfill, fail, timeout) is atomically paired with a commitment update — no HTLC should change state without a corresponding new commitment being signed and the old state revoked.
2. Check for crash recovery scenarios: if the process crashes between an HTLC state change and the commitment update, does recovery correctly reconcile the state?
3. Verify that the dApp does not have application-level HTLC states that diverge from the channel commitment state — the source of truth must be the signed commitment transactions.

Exploitability

1. An HTLC that is marked as "fulfilled" in the application database but not yet committed in a signed commitment transaction can be lost if the channel is force-closed — the force-close uses the latest committed state, which does not include the fulfillment.
2. Orphaned HTLC states can cause double-settlement: the application considers the payment settled (and delivers goods/services) but the channel state does not reflect the settlement, allowing the payer to eventually timeout the HTLC.
3. A counterparty can exploit orphaned states by triggering a force-close after an HTLC is settled in the application but before the commitment is updated.

Check

1. Bind HTLC state transitions atomically to commitment updates — use database transactions or state locks to ensure no intermediate states are visible.
2. Implement crash recovery that reconciles application state with the latest signed commitment transaction.
3. Add tests that simulate crashes between HTLC state changes and commitment updates, verifying correct recovery.

---

### Title: 0x0006-invoice-settlement-state-machine-must-guarantee-settlement-on-preimage-detection

Description
When a dApp detects that a preimage has been revealed (on any channel, on-chain, or through any side-channel), it must immediately attempt to settle all pending HTLCs that use the corresponding payment hash. Failure to do so creates a window where the counterparty can timeout the HTLC while the preimage is already known — the dApp loses the HTLC value because it had the preimage but did not use it in time.

Identify

1. Locate preimage detection handlers — search for `preimage_received`, `payment_settled`, `on_chain_claim_detected`, and any event handler that processes newly revealed preimages.
2. Find the HTLC settlement logic — search for `fulfill_htlc`, `settle_invoice`, and the code path from preimage detection to HTLC fulfillment across all channels.
3. Search for pending HTLC tracking — does the dApp maintain a mapping from `payment_hash` to all pending HTLCs that can be settled with the corresponding preimage?

Analyze

1. Verify that on preimage detection, the dApp immediately attempts to fulfill ALL pending HTLCs with matching `payment_hash` across all channels — not just the channel where the preimage was first detected.
2. Check that the settlement path is non-blocking and has retry logic — if the first settlement attempt fails (channel temporarily unavailable, commitment in-flight), the system must retry before the HTLC timeout.
3. Verify that preimages learned from on-chain transactions (e.g., a counterparty claiming an HTLC-success transaction) trigger upstream settlement.

Exploitability

1. A forwarding node learns the preimage from the downstream channel but does not immediately settle the upstream HTLC. If the upstream counterparty force-closes and the HTLC timeout expires before settlement, the forwarding node loses the HTLC value despite having the preimage.
2. In a swap service, the preimage is revealed on-chain (counterparty claims the on-chain HTLC) but the service does not settle the corresponding LN invoice — the LN payment times out and the service loses the swap amount.

Check

1. Implement a preimage event handler that immediately triggers settlement attempts on all pending HTLCs with matching `payment_hash`.
2. Add retry and escalation logic: if settlement fails, retry with increasing urgency up to force-close if necessary.
3. Add tests that reveal a preimage on one channel and verify automatic settlement on all other channels with matching pending HTLCs.

---

### Title: 0x0007-submarine-swap-must-enforce-atomicity-via-hashlock-binding-and-timelock-ordering

Description
A submarine swap (on-chain → Lightning) is atomic only if: (a) both legs are locked to the same `payment_hash` (hashlock binding), and (b) the on-chain refund timeout is strictly after the LN payment timeout plus a safety budget (timelock ordering). Violations of either condition allow one party to claim both legs of the swap.

Identify

1. Locate the submarine swap flow — search for on-chain HTLC construction, LN invoice creation, and the coordination between the two payment legs.
2. Find the hashlock binding — verify that the on-chain HTLC and the LN invoice use the exact same `payment_hash`.
3. Find the timelock ordering — compare the on-chain refund timeout (`cltv_expiry` on the refund script path) with the LN invoice expiry and identify the safety margin between them.

Analyze

1. Verify hashlock binding: the on-chain HTLC script uses `OP_SHA256 <payment_hash> OP_EQUALVERIFY` with the exact same `payment_hash` derived from the LN invoice. If different hashes are used, the legs are not atomically linked.
2. Verify timelock ordering: `on_chain_refund_timeout > ln_invoice_expiry + safety_budget` where `safety_budget >= 18 blocks` (minimum) or `>= 72 blocks` (recommended). See `timelock-safety-budget.md` reference.
3. Check for confirmation depth requirements: the on-chain HTLC must have sufficient confirmations before the service reveals the preimage (settles the LN invoice). See checkpoint 0x0000.

Exploitability

1. If the on-chain refund timeout <= LN invoice expiry, the user can claim the on-chain refund AND receive the LN payment — both legs execute, and the service loses the swap amount.
2. If different `payment_hash` values are used for the on-chain and LN legs, the preimage revealed on one leg does not unlock the other — one party ends up with both the preimage and the locked funds.
3. If the safety budget is too small, a fee spike during congestion can prevent the service from claiming the on-chain HTLC before the refund timeout, allowing the user to refund after the preimage is already revealed.

Check

1. Enforce identical `payment_hash` across both legs of the submarine swap — derive both from the same preimage.
2. Enforce timelock ordering: `refund_timeout >= ln_expiry + safety_budget` with `safety_budget >= 72 blocks` for mainnet.
3. Add tests that attempt to claim both legs of the swap simultaneously and verify atomicity holds under various timing conditions.

---

### Title: 0x0008-reverse-swap-timelock-must-prevent-simultaneous-on-chain-claim-and-lightning-timeout

Description
In a reverse swap (Lightning → on-chain), the user holds the preimage and pays via LN, while the service locks on-chain funds to the same `payment_hash`. The critical race condition is: after the service settles the LN invoice (learns the preimage), the user claims the on-chain HTLC, but the service's on-chain refund timeout may also become available — if both are claimable simultaneously, the service can get the LN payment AND reclaim the on-chain funds.

Identify

1. Locate the reverse swap flow — search for on-chain HTLC creation by the service, LN payment by the user, and the preimage flow from LN settlement to on-chain claim.
2. Find the service's on-chain refund timeout and compare it to the LN payment timeout and the user's expected claim window.
3. Search for the user's on-chain claim logic — how quickly does the user claim after the preimage is available?

Analyze

1. Verify that `service_refund_timeout > ln_payment_timeout + safety_budget` — the service must not be able to refund on-chain while the LN payment can still settle.
2. Check that the user has sufficient time to claim on-chain after learning the preimage — `user_claim_window = service_refund_timeout - preimage_available_time - B_conf` must be positive and adequate.
3. Verify that the service cannot race the user: once the preimage is revealed (LN settlement), the user must be able to claim on-chain before the service's refund path opens.

Exploitability

1. If `service_refund_timeout <= ln_payment_timeout`, the service can refund on-chain while the LN payment is still propagating — the service gets both the refund and the LN payment.
2. If the user's claim window is too small (e.g., < safety_budget), a fee spike can prevent the user's on-chain claim from confirming before the service's refund timeout — the service refunds and keeps the LN payment.
3. A malicious service can deliberately set a tight refund timeout to engineer the race condition, profiting from users who cannot claim in time.

Check

1. Enforce timelock ordering: `service_refund_timeout >= ln_payment_timeout + safety_budget` with adequate safety margin.
2. Verify the user's claim window is sufficient for on-chain confirmation under adversarial fee conditions.
3. Add tests that simulate the race condition (service refund vs user claim) under various timing and fee scenarios.

---

### Title: 0x0009-channel-force-close-must-have-fee-budget-sufficient-for-adversarial-mempool-conditions

Description
Force-closing a Lightning channel requires broadcasting a commitment transaction and potentially HTLC-timeout/success transactions. These transactions have pre-signed fee rates determined at commitment time, which may be far below the actual fee market when the force-close is needed (e.g., during congestion or adversarial conditions). Without sufficient fee budget and fee-bumping capability (anchor outputs + CPFP), a force-close can be stuck in the mempool, preventing HTLC timeout enforcement within the required timelock windows.

Identify

1. Locate force-close logic — search for commitment transaction broadcast, HTLC-timeout/success transaction construction, and anchor output handling.
2. Find fee estimation and fee-bumping mechanisms — search for CPFP (Child-Pays-For-Parent) logic, anchor output spending, and fee reserve management.
3. Search for UTXO reserve requirements — does the node maintain a reserve specifically for fee bumping force-close transactions?

Analyze

1. Verify that the node uses anchor outputs (BOLT #3) for commitment transactions, enabling post-broadcast fee bumping via CPFP.
2. Check that a UTXO reserve is maintained specifically for CPFP fee bumping — this reserve must be separate from channel funds and sized for adversarial fee conditions (100+ sat/vB).
3. Verify that the fee-bumping logic accounts for the full transaction chain: commitment tx + HTLC-timeout/success txs, and that CPFP covers the effective fee rate for the entire package.

Exploitability

1. If the force-close commitment transaction has a fee rate of 5 sat/vB but the mempool minimum is 50 sat/vB, the transaction will not propagate or confirm. HTLC timelocks expire, and the counterparty can claim HTLC timeouts that should have been enforced.
2. An attacker can deliberately congest the mempool to prevent the victim's force-close from confirming, exploiting the insufficient fee budget to steal HTLC values.
3. Without a separate fee reserve, the node may not have UTXOs available for CPFP after the channel is closed — all funds are locked in the commitment transaction.

Check

1. Require anchor outputs on all commitment transactions and implement CPFP fee bumping with robust fee estimation.
2. Maintain a dedicated UTXO reserve for force-close fee bumping, sized at `max_expected_fee_rate * (commit_vsize + cpfp_vsize)`.
3. Add tests that simulate force-close during high-fee conditions and verify the fee-bumping mechanism achieves confirmation within the HTLC timelock window.

---

### Title: 0x000a-replacement-cycling-and-mempool-manipulation-must-not-defeat-timeout-enforcement

Description
Replacement cycling attacks use RBF (Replace-By-Fee) to repeatedly evict a victim's HTLC-timeout transaction from the mempool. The attacker broadcasts a conflicting higher-fee transaction (using the HTLC preimage claim path), then replaces their own transaction to recover fees, cycling the victim's transaction out until the upstream HTLC expires. This was demonstrated in 2023 against LN forwarding nodes and is a fundamental challenge for HTLC timeout enforcement.

Identify

1. Locate HTLC-timeout transaction broadcast logic — search for how the node handles timeout enforcement when a downstream HTLC is not settled.
2. Find mempool monitoring — does the node detect when its timeout transaction is evicted or replaced?
3. Search for replacement cycling mitigation — pre-signed transaction anchoring, transaction pinning, or re-broadcast strategies.

Analyze

1. Verify that the node detects when its HTLC-timeout transaction is evicted from the mempool (via mempool monitoring or transaction status polling).
2. Check that the node re-broadcasts the timeout transaction with increased fees when eviction is detected — the fee escalation must outpace the attacker's cycling budget.
3. Verify that the node uses transaction pinning strategies (large low-fee child transactions that make replacement expensive) or anchor outputs with aggressive CPFP to resist replacement.

Exploitability

1. The attacker cycles the victim's timeout transaction out of the mempool for the duration of the HTLC timelock. When the upstream HTLC expires, the victim cannot claim the timeout — the attacker then claims the downstream HTLC using the preimage, and the victim loses the forwarded value.
2. The attack cost is relatively low: the attacker only pays incremental relay fees per cycle, not the full replacement fee, because they replace their own transactions to recover funds.
3. Combined with a fee spike, the cycling attack becomes more effective because the victim's re-broadcast requires higher fees each cycle.

Check

1. Implement mempool monitoring and automatic re-broadcast with fee escalation for HTLC-timeout transactions.
2. Use anchor outputs and aggressive CPFP to make the timeout transaction expensive to replace.
3. Add tests that simulate replacement cycling (conflicting transactions evicting the timeout tx) and verify the node successfully confirms the timeout within the HTLC timelock.

---

### Title: 0x000b-on-chain-settlement-must-not-be-treated-as-final-before-sufficient-confirmation-depth

Description
On-chain transactions are subject to chain reorganizations (reorgs) that can reverse confirmed transactions. If a dApp treats an on-chain settlement (HTLC claim, swap execution, channel close) as final at 1 confirmation, a reorg can reverse the settlement while the dApp has already delivered goods, services, or revealed the preimage. The required confirmation depth depends on the value at risk and the adversary model.

Identify

1. Locate on-chain confirmation handling — search for block confirmation listeners, settlement finality logic, and the threshold at which the dApp considers an on-chain transaction final.
2. Find preimage revelation triggers tied to on-chain confirmations — does the dApp reveal the preimage or settle invoices based on on-chain confirmation count?
3. Search for swap settlement and channel close finality — how many confirmations are required before the dApp considers these operations complete?

Analyze

1. Verify that the dApp requires at least 3 confirmations (6 recommended) before treating on-chain settlement as final for preimage revelation or fund release.
2. Check that the confirmation depth scales with the value at risk — higher-value transactions should require more confirmations.
3. Verify that the dApp handles reorgs gracefully: if a previously confirmed transaction is unconfirmed (reorged), the dApp must revert any state changes based on that transaction.

Exploitability

1. In a submarine swap, the user's on-chain HTLC funding transaction receives 1 confirmation. The service settles the LN invoice (reveals preimage). A reorg removes the funding transaction — the user has the preimage and the on-chain funds, and the service lost the LN payment.
2. A miner with sufficient hashrate can deliberately create short reorgs to exploit low-confirmation-depth finality in swap services — mine a block with the funding transaction, wait for the service to settle, then orphan the block.

Check

1. Require at least 3 confirmations (6 for high-value operations) before treating on-chain settlement as final.
2. Implement reorg detection and state rollback for on-chain event handlers.
3. Add tests that simulate chain reorgs at various depths and verify the dApp correctly reverts state and does not release funds prematurely.

---

### Title: 0x000c-watchtower-must-detect-breaches-within-timelock-window-and-isolate-penalty-keys

Description
Watchtowers monitor the blockchain for revoked commitment transaction broadcasts and submit penalty (justice) transactions to claim all channel funds. The watchtower must detect breaches within the `to_self_delay` window (CSV timelock on the broadcaster's to_local output) and must have access to the revocation keys — but NOT to the channel's main signing keys. If the watchtower is offline during the dispute window or has excessive key access, it becomes either useless or a security liability.

Identify

1. Locate watchtower integration — search for breach hint transmission, penalty transaction pre-signing, and watchtower communication protocols.
2. Find the key material shared with the watchtower — determine whether the watchtower receives revocation secrets, full signing keys, or pre-signed penalty transactions.
3. Search for watchtower uptime monitoring and redundancy — does the dApp monitor watchtower availability and use multiple watchtowers?

Analyze

1. Verify that the watchtower can detect and respond to breaches within the `to_self_delay` window. The watchtower's monitoring latency + penalty transaction confirmation time must be less than the CSV delay.
2. Check key isolation: the watchtower should receive only the minimum key material needed to construct penalty transactions (revocation secrets + encrypted penalty blobs), NOT the node's main signing keys or channel state.
3. Verify that the dApp uses multiple independent watchtowers for redundancy — a single watchtower is a single point of failure.

Exploitability

1. If the watchtower is offline for the duration of the `to_self_delay` (e.g., 144 blocks = ~24 hours), a malicious counterparty can broadcast a revoked commitment and claim the funds after the CSV delay expires.
2. A watchtower with access to the node's signing keys can construct unauthorized transactions — a compromised watchtower becomes an attacker.
3. If breach hints (encrypted penalty transaction data) are not stored durably by the watchtower, a watchtower restart or database corruption can lose all breach detection capability.

Check

1. Verify watchtower uptime SLA covers the full `to_self_delay` window with margin for penalty transaction confirmation.
2. Enforce key isolation: watchtower receives encrypted penalty blobs and revocation secrets only, never main signing keys.
3. Add tests that simulate a breach during watchtower downtime and verify the consequences; also test that the watchtower correctly detects and penalizes breaches when online.

---

### Title: 0x000d-revocation-secrets-must-be-stored-durably-and-old-state-broadcast-must-trigger-penalty

Description
Every time a Lightning channel state is updated, the previous commitment transaction is revoked by exchanging revocation secrets (`revoke_and_ack`). The node must store these revocation secrets durably — loss of a revocation secret means the node cannot construct a penalty transaction if the counterparty broadcasts the corresponding revoked commitment. A dApp that loses revocation secrets (database corruption, migration bug, incomplete backup) permanently loses the ability to enforce penalties for those states.

Identify

1. Locate revocation secret storage — search for `revoke_and_ack` processing, revocation key derivation, and the persistent storage of per-commitment secrets.
2. Find backup and recovery mechanisms for the revocation secret database.
3. Search for old state detection logic — how does the node detect when a counterparty broadcasts a revoked commitment transaction?

Analyze

1. Verify that revocation secrets are stored in durable, redundant storage (not just in-memory) and that writes are fsynced/committed before the `revoke_and_ack` message is sent to the counterparty.
2. Check that the node can reconstruct penalty transactions from stored revocation secrets — the storage format must be sufficient to derive the revocation private key and construct the penalty spending transaction.
3. Verify that old state detection scans every new block for transactions matching known revoked commitment transaction patterns.

Exploitability

1. If revocation secrets are lost (database corruption, incomplete migration), the counterparty can broadcast any revoked state with impunity — the node cannot construct the penalty transaction, and the counterparty steals the state difference.
2. If revocation secrets are stored but the penalty transaction construction is buggy (wrong key derivation, incorrect script), the penalty fails despite having the secret — the counterparty's breach succeeds.
3. If old state detection is too slow (polling interval > `to_self_delay`), the breach is detected too late to submit the penalty transaction.

Check

1. Store revocation secrets in durable, redundant storage with write-ahead logging. Verify fsync before sending `revoke_and_ack`.
2. Test penalty transaction construction from stored revocation secrets — verify the penalty transaction is valid and spendable.
3. Add tests that broadcast revoked commitment transactions and verify the node detects the breach and submits a valid penalty transaction within the CSV delay window.

---

### Title: 0x000e-client-side-preimage-and-key-storage-must-be-encrypted-and-resistant-to-xss-exfiltration

Description
Browser-based Lightning wallets, web-embedded payment interfaces, and mobile LN apps store preimages and signing keys in client-side storage (localStorage, IndexedDB, Keychain, encrypted files). XSS vulnerabilities, malicious browser extensions, compromised CDN scripts, or mobile app compromise can exfiltrate these secrets, enabling the attacker to claim HTLCs, prove payments, or sign channel operations without authorization.

Identify

1. Locate client-side secret storage — search for preimage persistence (`localStorage`, `IndexedDB`, `SharedPreferences`, `Keychain`), key storage, and any plaintext secret handling in client code.
2. Find XSS attack surface — search for user-controlled content rendering, innerHTML usage, eval(), and third-party script inclusion that could enable script injection.
3. Search for encryption at rest — are stored preimages and keys encrypted with a user-derived key or hardware-backed keystore?

Analyze

1. Verify that preimages and signing keys are encrypted at rest using a key derived from user authentication (password, biometric) or stored in a hardware-backed keystore (Secure Enclave, TEE, hardware wallet).
2. Check that the web application implements Content Security Policy (CSP) headers that prevent inline script execution and restrict script sources.
3. Verify that no third-party scripts (analytics, UI libraries, polyfills) have access to the wallet's secret storage — use iframe isolation or Web Workers for sensitive operations.

Exploitability

1. An XSS vulnerability allows an attacker to execute JavaScript in the wallet's origin, reading all preimages and keys from localStorage/IndexedDB — the attacker can claim HTLCs, prove payments, and sign channel operations.
2. A malicious browser extension with `storage` or `tabs` permissions can read the wallet's stored secrets across all sites.
3. A compromised CDN serving a JavaScript dependency can inject code that exfiltrates secrets before the wallet's own code executes.

Check

1. Encrypt all preimages and keys at rest using a user-derived key (PBKDF2/Argon2 from password) or hardware-backed keystore. Never store plaintext secrets in browser storage.
2. Implement strict CSP headers: `script-src 'self'`, no `unsafe-inline`, no `unsafe-eval`. Subresource Integrity (SRI) for all external scripts.
3. Add tests that attempt to access stored secrets via simulated XSS injection and verify the encryption prevents plaintext exfiltration.

---

### Title: 0x000f-taproot-channel-key-path-must-not-bypass-script-path-spending-conditions

Description
Taproot channels (proposed in BOLT specifications for future deployment) use P2TR outputs for commitment transactions. The key path allows cooperative spending with a single aggregated signature, while script paths enforce unilateral close conditions (timelocks, HTLCs, penalty). If the Taproot internal key is controlled by a single party (or if the key aggregation is flawed), that party can bypass all script-path conditions by spending via the key path — circumventing timelocks, penalty mechanisms, and HTLC enforcement.

Identify

1. Locate Taproot channel output construction — search for P2TR output creation in commitment transactions, internal key computation, and Tapscript tree assembly.
2. Find the key path spending policy — determine who can spend via key path (should require cooperation of both channel parties via MuSig2).
3. Search for the internal key derivation — verify whether it is a MuSig2 aggregate of both parties' keys or a single party's key.

Analyze

1. Verify that the Taproot internal key for channel outputs is a MuSig2 aggregate of both channel parties' public keys — no single party should be able to spend via key path unilaterally.
2. Check that for outputs requiring unilateral spending conditions (revocable outputs, HTLC outputs), the key path either requires cooperation or is disabled (NUMS internal key).
3. Verify that the Tapscript tree contains the correct spending conditions: revocation paths, CSV-delayed local output, HTLC claim/timeout paths.

Exploitability

1. If the internal key is one party's public key instead of a MuSig2 aggregate, that party can unilaterally spend the commitment output via key path, bypassing all script conditions — timelocks, penalties, and HTLC enforcement are nullified.
2. A malicious implementation that claims to use MuSig2 for the internal key but actually uses a key controlled by the service can steal all channel funds at any time via key path.
3. If the key path is available on revocable outputs, the broadcasting party can spend immediately via key path, eliminating the CSV delay needed for penalty enforcement. Cross-reference `audit-psbt-security` checkpoint 0x000a for Taproot key-path trust model details.

Check

1. Verify that Taproot channel internal keys are MuSig2 aggregates requiring both parties for key-path spending.
2. For revocable outputs, verify that key path is either cooperative-only (MuSig2) or disabled (NUMS point).
3. Add tests that attempt unilateral key-path spending on commitment outputs and verify it fails without both parties' cooperation.

---

### Title: 0x0010-ptlc-adaptor-signature-must-not-leak-secret-through-nonce-reuse-or-malleability

Description
Point Time-Locked Contracts (PTLCs) replace hash locks with adaptor signatures based on elliptic curve point locks. Instead of revealing a preimage to claim a payment, the claimant completes an adaptor signature, revealing the secret scalar. If the adaptor signature scheme has nonce reuse (similar to MuSig2 nonce reuse — see `audit-psbt-security` checkpoint 0x000c) or signature malleability, the secret can be leaked prematurely or the adaptor can be forged, breaking the atomic link between payment legs.

Identify

1. Locate adaptor signature implementation — search for `adaptor_sign`, `adaptor_verify`, `extract_secret`, point lock operations, and Schnorr-based adaptor signature construction.
2. Find nonce generation for adaptor signatures — verify CSPRNG usage and one-time nonce enforcement.
3. Search for adaptor signature verification — does the receiving party verify the adaptor signature before accepting the PTLC?

Analyze

1. Verify that nonce generation for adaptor signatures uses a CSPRNG and that nonces are never reused across different adaptor signing operations — the algebraic extraction attack from MuSig2 nonce reuse applies identically to adaptor signatures.
2. Check that adaptor signature verification confirms the relationship `adaptor_sig + secret = valid_sig` holds — if the adaptor signature is not verified, a malformed adaptor can be submitted that does not reveal the correct secret upon completion.
3. Verify that the secret extraction from a completed adaptor signature is robust to malleability — the completed signature must uniquely determine the secret scalar.

Exploitability

1. Nonce reuse across two adaptor signing sessions reveals the signer's private key (same algebraic extraction as Schnorr nonce reuse: `x = (s1 - s2) / (e1 - e2)`).
2. A malformed adaptor signature that passes naive verification but does not properly encode the secret can be "completed" without actually revealing the correct secret — the counterparty believes the PTLC is settled but cannot extract the secret to settle the upstream leg.
3. Signature malleability allows an attacker to modify a completed adaptor signature so the extracted secret differs from the original — breaking the atomic link between PTLC legs.

Check

1. Use CSPRNG for all adaptor signature nonces and enforce one-time-use nonce management (same requirements as MuSig2 — see `audit-psbt-security` checkpoint 0x000c).
2. Verify adaptor signatures before accepting PTLCs — confirm the mathematical relationship between the adaptor signature, the adaptor point, and the expected secret point.
3. Add tests that attempt nonce reuse in adaptor signing, submit malformed adaptor signatures, and verify the system rejects them and does not leak the secret.
