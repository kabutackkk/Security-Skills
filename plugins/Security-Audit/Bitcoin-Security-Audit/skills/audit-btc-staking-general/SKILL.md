---
name: audit-btc-staking-general
description: Audits Bitcoin staking protocol implementations for covenant bypass vulnerabilities, EOTS slashing failures, timelock manipulation, delegation trust boundary violations, reward distribution exploits, and bridge/checkpoint integrity gaps. Produces a findings.md report with ranked vulnerabilities.
when_to_use: |
  Use when user mentions "BTC staking", "Babylon staking", "Bitcoin staking protocol", "covenant", "pre-signed transaction", "EOTS", "extractable one-time signature", "finality gadget", "BTC slashing", "Bitcoin unbonding", "timelock staking", "staking delegation", "@babylonlabs-io/btc-staking-ts", "OP_CHECKSEQUENCEVERIFY staking", "NUMS point staking" or asks about Bitcoin-native staking security, covenant enforcement, or slashing mechanism correctness.
  Do NOT use for EVM staking protocols (Lido, EigenLayer), wrapped BTC DeFi, or non-Babylon staking.
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

# BTC Staking Protocol Vulnerability Scanner

## 1. Introduction

Bitcoin-native staking protocols — most notably Babylon — enable BTC holders to stake their bitcoin to secure Proof-of-Stake (PoS) chains without transferring custody to a bridge, federation, or wrapped token. The core mechanism uses pre-signed transaction covenants to restrict how staked BTC can be spent: the staker creates a staking transaction that can only be spent through a predefined set of paths (unbonding, slashing, or reward withdrawal), each enforced by pre-signed transactions and timelocks.

The finality gadget uses Extractable One-Time Signatures (EOTS) — a Schnorr signature scheme where signing two different messages with the same key deterministically reveals the private key. If a staking validator equivocates (signs two conflicting blocks on the PoS chain), their EOTS private key is extracted, and a pre-signed slashing transaction burns or redistributes their staked BTC. This creates a cryptoeconomic security guarantee: validators risk losing their BTC if they misbehave on the PoS chain.

The security of this architecture depends on correct covenant construction (no unauthorized spending paths), EOTS key management (no false positive slashing), timelock calibration (sufficient time for slashing evidence submission), delegation trust boundaries (validators cannot unilaterally spend staked BTC), and bridge/checkpoint integrity (the PoS chain accurately reflects Bitcoin state). Failures in any of these components can result in loss of staked BTC, false slashing, bypassed economic security, or stuck funds.

This skill covers Babylon-style BTC staking, covenant emulation via pre-signed transactions, EOTS finality gadgets, slashing mechanisms, timelock-based unbonding, delegation and validator management, reward distribution, and bridge/checkpoint trust assumptions. All pseudocode uses Bitcoin transaction structure and Script semantics. For PSBT-specific construction vulnerabilities in staking flows, cross-reference the `audit-psbt-security` skill.

---

## 2. Purpose

This skill audits Bitcoin staking protocol implementations to detect covenant bypass vulnerabilities, EOTS slashing failures, timelock manipulation, delegation trust boundary violations, reward distribution exploits, and bridge/checkpoint integrity gaps in Babylon-style BTC staking systems.

---

## 3. When to Use This Skill

**Prompt trigger**

```
Does the code implement BTC staking with covenant-based spending restrictions? ──yes──> Use this skill
│
no
│
v
Does it use EOTS or a finality gadget for PoS chain security backed by BTC? ──yes──> Use this skill
│
no
│
v
Does it construct pre-signed transaction sets for staking lifecycle management? ──yes──> Use this skill
│
no
│
v
Does it handle staking delegation, validator selection, or slashing on Bitcoin? ──yes──> Use this skill
│
no
│
v
Does it manage timelock-based unbonding or withdrawal of staked BTC? ──yes──> Use this skill
│
no
│
v
Skip this skill
```

**Concrete triggers**

- Staking transaction construction (covenant outputs, pre-signed unbonding transactions, slashing transactions)
- EOTS operations (`EOTS_Sign`, `EOTS_Extract`, `EOTS_Verify`, Schnorr one-time key usage, equivocation detection)
- Covenant enforcement via pre-signed transactions, `OP_CHECKTEMPLATEVERIFY` (OP_CTV), or Taproot script trees with restricted spending paths
- Timelock scripts (`OP_CHECKLOCKTIMEVERIFY`, `OP_CHECKSEQUENCEVERIFY`, `nLockTime`, `nSequence`, unbonding period)
- Delegation management (validator registration, stake delegation, validator key rotation, commission rates)
- Slashing conditions (equivocation evidence, slashing transaction construction and broadcast, false positive prevention)
- Reward distribution (on-chain vs off-chain rewards, reward claiming, verifiable reward computation)
- Bridge/checkpoint operations (Bitcoin light client, SPV proofs, checkpoint submission, reorg handling)
- Taproot outputs with restricted spending policies (NUMS internal key, script-path-only outputs, multi-path covenant trees)
- TypeScript SDK: `import * as bitcoin from "bitcoinjs-lib"`, `bitcoin.payments.p2tr`, `toXOnly`
- TypeScript SDK: `@babylonlabs-io/btc-staking-ts`, `buildStakingTransaction`, `preSignSlashingTx`
- TypeScript SDK: EOTS key management, `eotsSign`, `extractEOTSPrivateKey`, equivocation detection
- TypeScript SDK: `OP_CHECKSEQUENCEVERIFY`, `OP_CHECKLOCKTIMEVERIFY`, timelock script compilation

## Additional resources

- For real-world TypeScript vulnerable patterns in BTC staking implementations, see [typescript-vulnerable-patterns.md](references/typescript-vulnerable-patterns.md)

---

## Goal

Produce a `findings.md` file containing all identified vulnerabilities in the target BTC staking protocol implementation, each with a title, code location, description, attack scenario, and fix recommendation. Every checkpoint in the checklist below must be evaluated. The audit is complete when all checkpoints have been checked and all findings are reported.

## Workflow

### Step 1: Establish scope
Identify the target files and modules that handle staking covenants, EOTS operations, slashing logic, delegation, timelocks, or bridge/checkpoint verification. Confirm the project implements Babylon-style BTC staking and matches this skill's domain.

**Artifacts**: list of target files, confirmed project type
**Success criteria**: The target file set is known and confirmed to involve BTC staking protocol logic.

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
- For PSBT-specific construction vulnerabilities in staking flows, note the cross-reference to `audit-psbt-security` but do not execute it.

---

## 4. Checklist

### Title: 0x0000-staking-covenant-must-enforce-spending-restrictions-without-trusted-third-party

Description
A staking covenant restricts how staked BTC can be spent — typically limiting spending to a predefined set of paths (unbonding, slashing, or emergency recovery). On Bitcoin without native covenant opcodes (pre-OP_CTV), covenants are emulated using pre-signed transactions: the staker signs transactions for each allowed spending path before locking their BTC, then deletes the signing key or delegates it to a committee. If the covenant emulation is incomplete, an unauthorized spending path can bypass the staking restrictions.

Identify

1. Find the staking transaction output construction — locate the Taproot output (or P2WSH) that locks the staked BTC and identify all spending paths encoded in the script tree.
2. Locate the pre-signed transaction set — find where unbonding, slashing, and any other covenant transactions are constructed and signed before the staking transaction is broadcast.
3. Search for the signing key lifecycle — determine whether the key used for covenant construction is deleted, held by a committee, or retained by any single party.

Analyze

1. Verify that every possible spending path for the staking output is accounted for — enumerate all Tapscript leaves and verify each corresponds to a legitimate protocol action (unbonding, slashing, emergency recovery).
2. Check that the key-path spend on the Taproot staking output is disabled (NUMS internal key with no known discrete log) or requires multi-party cooperation — a single party with key-path access can bypass all script-path restrictions.
3. Verify that the pre-signed transactions cover all protocol state transitions and that no transition is missing — a missing pre-signed transaction means that state transition cannot occur, potentially locking funds permanently.

Exploitability

1. If the Taproot internal key for the staking output is a real key (not NUMS), the key holder can spend the staked BTC at any time via key path, bypassing all timelock, slashing, and unbonding conditions — effectively stealing the staked funds.
2. If the pre-signed transaction set is missing a state transition (e.g., no emergency recovery path), a protocol failure (buggy PoS chain, offline validator) can permanently lock the staked BTC.
3. A committee holding the covenant key can collude to spend staked BTC through the key path, bypassing the covenant — the committee becomes a trusted third party that the covenant was supposed to eliminate.

Check

1. Use a NUMS (Nothing-Up-My-Sleeve) point as the Taproot internal key for staking outputs — this provably disables key-path spending.
2. Enumerate and verify all script-path leaves against the protocol specification — every legitimate spending path must have a corresponding leaf, and no unauthorized leaves should exist.
3. Add tests that attempt key-path spending on staking outputs and verify it fails, and that attempt spending via unauthorized script paths and verify they are rejected.

---

### Title: 0x0001-pre-signed-transaction-set-must-cover-all-protocol-state-transitions

Description
In covenant emulation via pre-signed transactions, the staker pre-signs a complete set of transactions representing every possible protocol state transition before locking their BTC. If any state transition is missing from the pre-signed set, that transition becomes impossible — the staked BTC is either permanently locked in that state or must rely on a trusted party to facilitate the transition.

Identify

1. Find the protocol state machine — locate the documentation or code that defines all valid states (staked, unbonding, slashed, withdrawn, emergency recovery) and transitions between them.
2. Locate the pre-signed transaction construction — find where each state transition is encoded as a pre-signed transaction and verify the set is complete against the state machine.
3. Search for conditional transitions — some transitions may only be valid under certain conditions (e.g., slashing only after equivocation evidence, unbonding only after minimum staking period). Verify these conditions are enforced in the pre-signed transactions.

Analyze

1. Verify completeness: for every state transition in the protocol state machine, a corresponding pre-signed transaction exists. Map each transition to its pre-signed transaction.
2. Check that conditional transitions use appropriate Script conditions — timelocks (`OP_CHECKLOCKTIMEVERIFY`, `OP_CHECKSEQUENCEVERIFY`) for time-based conditions, hash locks for evidence-based conditions, and multi-signature for authorization-based conditions.
3. Verify that the pre-signed transaction chain is valid — each transaction's inputs correctly reference the outputs of the preceding state, and all amounts, fees, and scripts are consistent.

Exploitability

1. A missing unbonding transaction means the staker cannot voluntarily exit their staking position — their BTC is locked until the staking period expires (if there is a timelock) or permanently (if there is no timelock fallback).
2. A missing slashing transaction means equivocation cannot be punished — the finality gadget has no economic teeth, and validators can equivocate without consequence.
3. A missing emergency recovery transaction means that if the PoS chain halts, the covenant committee is compromised, or the protocol has a bug, the staked BTC is permanently locked.

Check

1. Define the complete state machine with all states and transitions, then verify one-to-one mapping to the pre-signed transaction set.
2. Include an emergency recovery path — a timelock-based fallback that allows the staker to recover their BTC after an extended period (e.g., 52,560 blocks / ~1 year) regardless of protocol state.
3. Add tests that exercise each pre-signed transaction in the set, verify they are valid when their conditions are met, and verify the staked BTC is recoverable through at least one path from every protocol state.

---

### Title: 0x0002-covenant-emulation-via-pre-signed-tx-must-not-allow-unauthorized-spending-paths

Description
Pre-signed transaction covenants enforce spending restrictions by ensuring the staker only signs transactions for authorized spending paths. However, if the staker retains the private key used to create the staking output (or if the key is derivable), they can create new transactions spending the staking output outside the pre-signed set — bypassing the covenant entirely. Secure covenant emulation requires that the signing key for the staking output is either destroyed or distributed among multiple parties (a "covenant committee") after the pre-signed transactions are created.

Identify

1. Find the key management for the staking output — locate where the private key used to sign pre-signed transactions is generated, used, and (hopefully) destroyed.
2. Search for key derivation paths — determine whether the staking output key is derived from a master key (HD wallet derivation) that the staker retains.
3. Locate any "covenant committee" or multi-party key management — determine whether the staking output uses a multi-signature scheme where multiple parties must cooperate to create new spending transactions.

Analyze

1. Verify that the private key for the staking output is provably destroyed after pre-signed transactions are created — this is the only way to guarantee no unauthorized transactions can be created.
2. If key destruction is not used, verify that the staking output uses a multi-party scheme (e.g., MuSig2 with a covenant committee) where no single party can produce a valid signature without cooperation from a threshold of parties.
3. Check that the key derivation path does not allow the staker to re-derive the staking output key from their HD wallet master seed — if the staker can re-derive the key, they can bypass the covenant at will.

Exploitability

1. A staker who retains the private key for their staking output can create a new transaction spending the staked BTC to themselves at any time — bypassing unbonding timelocks, avoiding slashing, and withdrawing staked BTC without protocol authorization.
2. If the staking output key is derived from an HD wallet path that the staker controls (e.g., `m/86'/0'/0'/0/N`), the staker can regenerate the key even if the original was deleted from memory — the HD seed is sufficient to re-derive it.
3. A compromised covenant committee member can collude with the staker (or act alone if they hold enough threshold shares) to bypass the covenant.

Check

1. Implement verifiable key destruction: use a key generation ceremony where the staking output key is generated in a secure enclave and the key material is provably destroyed after signing the pre-signed transaction set.
2. Alternatively, use a covenant committee with distributed key generation (DKG) where the full private key never exists in any single location — each committee member holds a share, and a threshold (e.g., 2-of-3) must cooperate to sign.
3. Add tests that attempt to create unauthorized transactions spending the staking output after the covenant is established, and verify they fail (key unavailable or threshold not met).

---

### Title: 0x0003-eots-finality-gadget-must-extract-key-on-equivocation-without-false-positives

Description
Extractable One-Time Signatures (EOTS) are the cryptographic foundation of BTC staking finality gadgets. EOTS is a Schnorr-based scheme where each signing key is intended for exactly one signature. If the key is used to sign two different messages, the private key can be algebraically extracted from the two signatures. This property is used for slashing: if a validator signs two conflicting blocks (equivocation), their EOTS private key is extracted, and a pre-signed slashing transaction (which requires that private key) becomes executable. False positives — extracting a key without actual equivocation — would unjustly slash honest validators.

Identify

1. Find the EOTS implementation — locate the key generation, signing, verification, and key extraction functions.
2. Search for the equivocation detection logic — find where two conflicting signatures from the same EOTS key are identified and the key extraction is triggered.
3. Locate the connection between EOTS key extraction and slashing transaction execution — verify that the extracted key is used to sign/authorize the pre-signed slashing transaction.

Analyze

1. Verify the EOTS algebraic correctness: given two Schnorr signatures `(R, s1)` and `(R, s2)` on different messages `m1` and `m2` with the same nonce `R`, the private key `x` is extracted as `x = (s1 - s2) / (e1 - e2) mod n` where `e1 = H(R || P || m1)` and `e2 = H(R || P || m2)`.
2. Check that EOTS key extraction requires exactly two signatures with the SAME nonce `R` on DIFFERENT messages — extraction must not be triggered by two signatures with different nonces (which would be normal multi-use of a regular Schnorr key) or two signatures on the same message (which would be re-signing, not equivocation).
3. Verify that the EOTS nonce `R` is deterministically bound to the signing context (block height, round number) so that honest validators who sign the same message at the same height always produce the same `R` — this prevents false extraction from honest re-signing.

Exploitability

1. A false positive extraction (extracting a key without real equivocation) allows an attacker to slash an honest validator. This can occur if the equivocation detection logic does not properly verify that the two signatures are on DIFFERENT messages — accepting two signatures on the same message as equivocation.
2. If the EOTS nonce binding is weak (e.g., nonce depends only on the private key and not on the block height or round), a validator who is asked to re-sign the same block (due to network issues) may produce a second signature with a different nonce, which looks like equivocation to an observer who only sees the nonce `R` values differ.
3. An attacker who compromises the EOTS key through a side channel (not through equivocation extraction) can trigger the slashing transaction on their own schedule, even if the validator has not equivocated.

Check

1. Verify EOTS algebraic correctness: unit test the key extraction formula against known-good test vectors, including edge cases (zero challenges, identical messages, boundary values).
2. Implement strict equivocation detection: require that the two conflicting signatures have the same public nonce `R` AND the same public key `P` AND different messages — reject extraction attempts that do not meet all three conditions.
3. Add tests that attempt false extraction scenarios (same message twice, different nonces on same message, signatures from different keys) and verify the extraction fails.

---

### Title: 0x0004-slashing-transaction-must-be-pre-signed-and-enforceable-without-validator-cooperation

Description
The slashing transaction is the enforcement mechanism for the finality gadget — it burns or redistributs the validator's staked BTC when equivocation is proven. This transaction must be pre-signed by the staker (as part of the covenant) before staking begins, so that it can be executed by anyone who obtains the EOTS private key through equivocation detection. If the slashing transaction requires the validator's active cooperation to execute, a malicious validator can simply refuse to participate in their own slashing.

Identify

1. Find the slashing transaction construction — locate where the slashing transaction is built, including its inputs (the staking output), outputs (burn address or redistribution), and the script conditions for execution.
2. Search for the slashing authorization mechanism — determine what is required to execute the slashing transaction. Is it the extracted EOTS key? A pre-signed signature? A multisig threshold?
3. Locate who can broadcast the slashing transaction — is it restricted to specific parties (covenant committee, PoS chain validators) or can anyone broadcast it once the EOTS key is extracted?

Analyze

1. Verify that the slashing transaction is fully constructed and pre-signed (or signable with the extracted EOTS key) before the staking transaction is broadcast — the slashing capability must exist from the moment staking begins.
2. Check that the slashing transaction does not require any input from the validator being slashed — it must be executable solely with the extracted EOTS private key plus any pre-existing covenant signatures.
3. Verify that the slashing transaction output is a burn address (provably unspendable, e.g., `OP_RETURN` or NUMS address) or a redistribution address that the slashed validator does not control.

Exploitability

1. If the slashing transaction requires the validator's online cooperation (e.g., a real-time signature from the validator), the validator can go offline or refuse to sign — making slashing unenforceable and the staking protocol's security guarantee empty.
2. If the slashing transaction output sends funds to an address the validator controls (e.g., an error in the burn address computation), the validator can equivocate and "slash" themselves to recover their funds — slashing becomes a no-op.
3. If the slashing transaction is not pre-signed and depends on a covenant committee to construct it after equivocation, the committee becomes a trusted party that can refuse to slash (or can be bribed by the validator).

Check

1. Pre-sign the slashing transaction as part of the staking covenant setup — the staker must sign the slashing transaction before broadcasting the staking transaction.
2. Make the slashing transaction executable by anyone — once the EOTS key is extracted, any party (a bounty hunter, a PoS chain validator, the covenant committee) can complete and broadcast the slashing transaction.
3. Add tests that simulate equivocation, extract the EOTS key, and execute the slashing transaction — verify the slashing transaction is valid on-chain and the staked BTC is burned or redistributed.

---

### Title: 0x0005-slashing-condition-must-not-be-triggerable-by-non-equivocation-events

Description
Slashing should only occur when a validator genuinely equivocates (signs two conflicting blocks at the same height). If the slashing condition can be triggered by non-equivocation events — such as network partitions, software bugs, clock drift, or malicious PoS chain behavior — honest validators can be unjustly slashed, losing their staked BTC without any malicious behavior on their part.

Identify

1. Find all code paths that can trigger slashing — locate every condition that leads to EOTS key extraction or slashing transaction execution.
2. Search for the equivocation evidence validation — determine what constitutes valid equivocation evidence and how it is verified.
3. Locate the slashing execution path and check whether there are alternative triggers beyond equivocation (e.g., inactivity penalties, timeout-based slashing, administrative slashing).

Analyze

1. Verify that slashing is triggered ONLY by cryptographic proof of equivocation — two valid EOTS signatures on different messages at the same block height from the same validator key.
2. Check that network partitions cannot cause false equivocation: if a validator signs block A on one partition and the other partition produces block B, the validator has not equivocated unless they also sign block B.
3. Verify that the PoS chain cannot fabricate equivocation evidence — the evidence must be independently verifiable using only the EOTS public key and the two conflicting signatures, without trusting the PoS chain's attestation.

Exploitability

1. A malicious PoS chain (or a majority of PoS validators) could fabricate false equivocation evidence to slash an honest BTC staker — if the evidence verification does not independently validate the EOTS signatures, the BTC staker has no defense.
2. Clock drift between the validator's machine and the PoS chain's view of block height can cause the validator to sign two blocks that appear to be at the same height from the chain's perspective but are at different heights from the validator's perspective — ambiguous equivocation.
3. Software bugs in the validator client that cause it to sign two proposals at the same height (e.g., a restart that replays a signing request) trigger genuine equivocation even though the validator had no malicious intent — this is a "foot-gun" that punishes honest but buggy validators.

Check

1. Require cryptographic proof of equivocation: two EOTS signatures with the same public key and same nonce `R` on different messages, independently verifiable without trusting the PoS chain.
2. Implement signing guardrails in the validator client: maintain a persistent log of signed block heights and refuse to sign a second block at the same height, even after restart.
3. Add tests that simulate non-equivocation events (network partition, restart, clock drift) and verify they do not trigger slashing.

---

### Title: 0x0006-unbonding-timelock-must-be-sufficient-for-slashing-evidence-submission

Description
The unbonding period is the delay between when a staker initiates withdrawal and when they can actually spend their unstaked BTC. This delay exists to allow time for equivocation evidence to be detected and submitted — if the unbonding period is too short, a validator can equivocate, immediately unbond, and withdraw their BTC before the slashing transaction can be constructed and broadcast, escaping punishment entirely.

Identify

1. Find the unbonding timelock value — locate where the `OP_CHECKSEQUENCEVERIFY` or `OP_CHECKLOCKTIMEVERIFY` value is set for the unbonding transaction.
2. Search for the slashing evidence submission pipeline — determine how long it takes from equivocation detection to slashing transaction broadcast, including evidence propagation, verification, key extraction, and transaction construction.
3. Locate any governance or parameter update mechanism that can modify the unbonding period after staking has begun.

Analyze

1. Verify that the unbonding period is strictly longer than the worst-case slashing evidence submission time — account for evidence detection delay (depends on PoS chain block time and finality), cross-chain communication delay (evidence must reach Bitcoin), key extraction computation time, slashing transaction construction and broadcast time, and Bitcoin block confirmation time.
2. Check that the unbonding period cannot be shortened after staking begins — if a governance action or parameter update can reduce the unbonding period for existing stakers, it creates a window for consequence-free equivocation.
3. Verify that the timelock is enforced at the Bitcoin Script level (using `OP_CSV` or `OP_CLTV`), not merely at the application level — application-level enforcement can be bypassed.

Exploitability

1. A validator equivocates on the PoS chain, immediately submits an unbonding transaction, and if the unbonding period (e.g., 100 blocks / ~17 hours) is shorter than the time needed to detect the equivocation, extract the EOTS key, construct the slashing transaction, and get it confirmed — the validator withdraws their BTC before slashing executes.
2. A governance attack that reduces the unbonding period for all existing stakers creates a window where equivocating validators can escape slashing — they unbond at the old (shorter) timelock while evidence submission assumes the old (longer) timelock.
3. Bitcoin congestion can delay slashing transaction confirmation — if the mempool is congested and slashing transactions compete for block space, the unbonding timelock may expire before the slashing transaction confirms.

Check

1. Set the unbonding period to at least 2x the worst-case slashing evidence submission time, accounting for Bitcoin congestion and cross-chain delays (e.g., Babylon uses ~3 days / ~432 blocks).
2. Make the unbonding period immutable for existing stakers — parameter updates should only apply to new staking positions.
3. Add tests that simulate equivocation followed by immediate unbonding, verifying that the slashing transaction can be constructed and confirmed before the unbonding timelock expires.

---

### Title: 0x0007-timelock-script-must-not-be-bypassable-via-alternative-spending-paths

Description
Timelock enforcement in staking protocols relies on Bitcoin Script opcodes (`OP_CHECKLOCKTIMEVERIFY`, `OP_CHECKSEQUENCEVERIFY`) embedded in the staking output's spending conditions. If the staking output has alternative spending paths that do not include timelock conditions — such as a Taproot key-path spend or a script-path leaf without timelocks — the timelock can be bypassed entirely.

Identify

1. Find all spending paths for the staking output — enumerate every Tapscript leaf and the key-path spending option.
2. Locate timelock enforcement in each spending path — verify that every path that should be time-restricted includes the appropriate `OP_CLTV` or `OP_CSV` opcode.
3. Search for the `nLockTime` and `nSequence` values in pre-signed transactions — these must be set correctly to satisfy the Script-level timelock checks.

Analyze

1. Verify that the Taproot key path is disabled (NUMS internal key) — key-path spending bypasses all script conditions, including timelocks.
2. Check each Tapscript leaf: every leaf that represents a time-restricted action (unbonding, withdrawal) must include `OP_CHECKLOCKTIMEVERIFY` or `OP_CHECKSEQUENCEVERIFY` with the correct timelock value.
3. Verify that pre-signed transactions set `nLockTime` or `nSequence` values that satisfy the Script-level timelock — `OP_CLTV` checks `nLockTime >= timelock_value` and `OP_CSV` checks `nSequence >= relative_timelock_value`.

Exploitability

1. A Taproot key-path spend (if the internal key is not NUMS) bypasses all Tapscript conditions — the spender does not need to satisfy any timelock, multisig, or hash-lock condition.
2. A Tapscript leaf that is intended for unbonding but omits `OP_CSV` allows the staker to unbond immediately without waiting for the unbonding period — the timelock is not enforced.
3. A pre-signed unbonding transaction with `nSequence = 0xFFFFFFFF` (which disables relative timelock) will fail the `OP_CSV` check — but if the staker creates a new transaction with the correct `nSequence` (possible if they retain the key), they can bypass the pre-signed transaction's intended timelock by choosing a shorter one.

Check

1. Use a NUMS internal key for all staking outputs to disable key-path spending.
2. Verify that every time-restricted Tapscript leaf includes the correct `OP_CLTV` or `OP_CSV` opcode with the intended timelock value.
3. Add tests that attempt to spend staking outputs before the timelock expires via every available spending path, confirming all paths enforce the timelock.

---

### Title: 0x0008-staking-transaction-must-commit-to-exact-unbonding-and-slashing-outputs

Description
The staking transaction creates the covenant output that locks the staked BTC. The pre-signed unbonding and slashing transactions spend this output. If the staking transaction does not commit to the exact outputs of the unbonding and slashing transactions (e.g., through Tapscript hash verification or output amount commitments), a malicious party could substitute the unbonding or slashing destination addresses, redirecting funds during these critical operations.

Identify

1. Find the staking transaction output script — determine what spending conditions are encoded and whether they commit to specific output addresses or amounts.
2. Locate the pre-signed unbonding and slashing transactions — verify that their output addresses and amounts are fixed at the time the staking covenant is established.
3. Search for any mechanism that allows modifying the unbonding or slashing destination after the staking transaction is confirmed (e.g., a governance-controlled address update, a committee-signed address change).

Analyze

1. Verify that the pre-signed unbonding transaction output sends the staked BTC (minus fees) back to the staker's specified withdrawal address — and that this address is committed in the pre-signed transaction and cannot be changed.
2. Check that the pre-signed slashing transaction output sends the slashed BTC to a burn address or redistribution contract — and that this address is committed and cannot be redirected.
3. Verify that the fee amount in pre-signed transactions is reasonable and bounded — an inflated fee in the slashing transaction could make slashing more expensive than the penalty, discouraging slashing enforcement.

Exploitability

1. If the unbonding transaction's output address can be modified after staking (e.g., the covenant committee can redirect unbonding funds), the committee can steal staked BTC by "unbonding" to their own address.
2. If the slashing transaction's burn address is not fixed, a validator could arrange for the slashing funds to go to an address they control — slashing becomes a self-transfer rather than a penalty.
3. If the pre-signed transaction fees are set too high, the staker loses more value to fees than the protocol intends — this is a silent value extraction attack.

Check

1. Commit all output addresses and amounts in the pre-signed transactions at covenant setup time — no post-setup modification of destinations should be possible.
2. Verify that the slashing transaction burn address is provably unspendable (e.g., `OP_RETURN` output or NUMS address with published derivation showing no known private key).
3. Add tests that attempt to modify unbonding and slashing transaction outputs after the staking covenant is established, confirming the modifications invalidate the covenant.

---

### Title: 0x0009-delegation-must-not-grant-validator-unilateral-spending-authority-over-staked-btc

Description
In staking delegation, a BTC holder delegates their stake to a validator who performs PoS duties on their behalf. The delegation must not grant the validator the ability to unilaterally spend the staked BTC — the validator should only have the authority to sign PoS chain blocks (via EOTS), not to move the underlying BTC. If the delegation mechanism confuses PoS signing authority with BTC spending authority, the validator can steal the delegator's staked BTC.

Identify

1. Find the delegation mechanism — locate where the staker delegates to a validator and what keys or permissions are shared.
2. Search for the separation between EOTS signing keys (used for PoS finality) and BTC spending keys (used for the staking covenant) — verify these are independent key pairs.
3. Locate the staking output's spending conditions — determine whether any spending path is authorized by the validator's key alone (without the staker's key or a covenant committee).

Analyze

1. Verify that the validator receives only the EOTS signing key (or the authority to sign on the PoS chain), NOT the BTC spending key for the staking output.
2. Check that no spending path in the staking covenant can be satisfied by the validator's key alone — every spending path should require the staker's key, the covenant committee's key, or a combination.
3. Verify that the delegation is revocable — the staker can revoke delegation and reassign to a different validator without moving their staked BTC.

Exploitability

1. If the delegation grants the validator a key that can sign a spending transaction for the staking output (even as one of multiple required signers in a 1-of-N or threshold scheme where the validator has enough shares), the validator can unilaterally spend the staked BTC.
2. If the EOTS signing key and the BTC spending key are derived from the same master key or share material, compromising the EOTS key (through equivocation extraction) also compromises the BTC spending key — the staker's BTC is stolen as a side effect of the slashing mechanism.
3. A validator who accumulates enough delegated EOTS keys can perform a "mass equivocation" attack: equivocate on the PoS chain, trigger slashing for all delegators, and if the slashing mechanism has a bug (checkpoint 0x0004), potentially recover the funds.

Check

1. Use completely independent key pairs for EOTS signing (PoS duties) and BTC spending (covenant operations) — derive them from different paths or generate them independently.
2. Ensure no spending path in the staking covenant is satisfiable by the validator's keys alone — require staker cooperation or covenant committee threshold for all BTC movement.
3. Add tests that attempt to spend the staking output using only the validator's keys and verify the spending fails.

---

### Title: 0x000a-validator-key-rotation-must-not-invalidate-existing-slashing-enforceability

Description
Validators may need to rotate their EOTS signing keys for operational security (key compromise, hardware migration, regular rotation). Key rotation must not invalidate the slashing mechanism for existing staking positions — if old pre-signed slashing transactions depend on the old EOTS key, and the validator rotates to a new key, the old slashing transactions may become unexecutable because equivocation with the new key does not reveal the old key.

Identify

1. Find the key rotation mechanism for validators — locate where EOTS keys are updated and how the protocol handles the transition.
2. Search for the relationship between the EOTS key and the pre-signed slashing transaction — determine whether the slashing transaction's execution depends on extracting the specific EOTS key that was active when the staking covenant was created.
3. Locate re-registration or re-staking flows that might require creating new pre-signed transactions after key rotation.

Analyze

1. Verify that key rotation triggers re-creation of the pre-signed slashing transaction set — the new slashing transaction must be executable using the new EOTS key (extracted on equivocation with the new key).
2. Check the transition period: during key rotation, there may be a window where both old and new keys are valid. Verify that slashing is enforceable for equivocation with either key during this window.
3. Verify that old pre-signed slashing transactions are invalidated after key rotation — they should no longer be executable, since the old EOTS key is no longer used for signing and equivocation with the old key cannot occur.

Exploitability

1. A validator rotates their EOTS key and the old slashing transaction (which depends on the old key) becomes unexecutable. The validator then equivocates using the new key, but no slashing transaction exists for the new key — the validator escapes slashing.
2. During the key rotation transition, the validator uses the old key for equivocation (which would trigger slashing via the old slashing transaction) but the protocol has already invalidated the old slashing transaction — equivocation goes unpunished.
3. Rapid key rotation can be used to repeatedly invalidate slashing transactions faster than they can be reconstructed — a denial-of-slashing attack.

Check

1. Require new pre-signed slashing transactions (signed by the staker) for every key rotation — the staker must create and submit new covenant transactions before the rotation takes effect.
2. Enforce a minimum interval between key rotations to prevent rapid rotation attacks.
3. Add tests that simulate key rotation followed by equivocation with the new key, verifying that the new slashing transaction is executable and the old one is invalidated.

---

### Title: 0x000b-reward-distribution-must-be-verifiable-and-not-depend-on-trusted-oracle-alone

Description
BTC stakers earn rewards for securing the PoS chain (typically paid in the PoS chain's native token or in BTC via a bridge). The reward computation and distribution must be verifiable — stakers should be able to independently confirm that their rewards are calculated correctly and that the distribution is fair. A system that depends entirely on a trusted oracle or centralized reward distributor is vulnerable to reward theft, unfair distribution, or oracle manipulation.

Identify

1. Find the reward computation logic — locate where staking rewards are calculated (based on stake weight, delegation period, PoS chain performance, etc.).
2. Search for the reward distribution mechanism — are rewards distributed on-chain (verifiable) or off-chain (requires trust)?
3. Locate any oracle or bridge dependency in the reward pipeline — determine what external data feeds (PoS chain block rewards, stake participation rates) are required.

Analyze

1. Verify that the reward computation is deterministic and reproducible — given the same inputs (stake amount, staking duration, PoS chain performance data), any party should compute the same reward amount.
2. Check that reward claims include a cryptographic proof (Merkle proof, state proof from the PoS chain, or ZK proof) that the reward amount is correct — the staker should not have to trust the distributor's calculation.
3. Verify that the reward distribution mechanism cannot be front-run, sandwiched, or manipulated by the distributor — e.g., the distributor cannot selectively withhold rewards from specific stakers.

Exploitability

1. A trusted reward oracle that over-reports certain stakers' rewards and under-reports others enables reward theft — the oracle operator or a colluding party claims excess rewards.
2. A centralized reward distributor can withhold rewards from specific stakers without detection — if the distribution is not cryptographically verifiable, stakers cannot prove they were underpaid.
3. If rewards are computed based on PoS chain data that is relayed through a bridge, the bridge operator can manipulate the relay data to alter reward amounts.

Check

1. Implement verifiable reward distribution: each reward claim should include a cryptographic proof (Merkle proof of inclusion in a reward root, or state proof from the PoS chain) that can be independently verified.
2. Publish the complete reward computation (inputs, formula, outputs) so stakers can independently verify their rewards.
3. Add tests that verify reward computations against known-good test vectors and that detect discrepancies between the distributor's claimed rewards and independently computed rewards.

---

### Title: 0x000c-bridge-checkpoint-must-be-independently-verifiable-on-both-chains

Description
BTC staking protocols bridge between Bitcoin and a PoS chain — the PoS chain must know about Bitcoin state (staking transactions, slashing evidence) and Bitcoin must know about PoS chain state (equivocation proofs, reward claims). This cross-chain communication relies on checkpoints or light client proofs. If checkpoints are not independently verifiable on both chains, a compromised bridge can fabricate state, enabling false slashing, phantom staking (claiming rewards without actually staking), or checkpoint censorship.

Identify

1. Find the checkpoint submission mechanism — locate where Bitcoin state is relayed to the PoS chain and where PoS chain state is relayed to Bitcoin.
2. Search for checkpoint verification — how does each chain verify the checkpoint from the other chain? SPV proofs? Full header chain? Trusted relayer?
3. Locate the trust model for the bridge — is it a federated bridge (trusted committee), an optimistic bridge (fraud proofs), or a light client bridge (cryptographic verification)?

Analyze

1. Verify that the PoS chain verifies Bitcoin block headers against the Bitcoin consensus rules (proof-of-work validation, difficulty adjustment, header chain continuity) — a Bitcoin light client on the PoS chain should validate headers rather than trusting a relayer.
2. Check that Bitcoin-side verification of PoS chain state uses cryptographic proofs (consensus signatures, Merkle state proofs) rather than trusting a single relayer or committee.
3. Verify that checkpoint submission cannot be censored — if a single entity controls checkpoint submission, they can prevent slashing evidence from reaching Bitcoin or prevent reward claims from reaching the PoS chain.

Exploitability

1. A compromised relayer submits a fake Bitcoin checkpoint to the PoS chain, showing a staking transaction that does not exist on Bitcoin — the PoS chain grants staking power and rewards to a phantom staker.
2. A censoring bridge operator withholds equivocation evidence from Bitcoin, preventing slashing transactions from being constructed — the equivocating validator escapes punishment.
3. A relayer submits an outdated Bitcoin checkpoint to the PoS chain, causing the PoS chain to believe a staker is still active when they have already unbonded on Bitcoin — the staker receives rewards without providing security.

Check

1. Implement a Bitcoin light client on the PoS chain that validates block headers against proof-of-work rules — do not trust a relayer for header validity.
2. Implement permissionless checkpoint submission — allow anyone to submit checkpoints and earn a reward, preventing checkpoint censorship by a single party.
3. Add tests that submit fake checkpoints (invalid proof-of-work, inconsistent header chain, fabricated staking transactions) and verify the light client rejects them.

---

### Title: 0x000d-btc-light-client-on-host-chain-must-handle-reorgs-and-difficulty-adjustment

Description
A Bitcoin light client running on the PoS chain (host chain) must handle Bitcoin-specific consensus mechanics: chain reorganizations (reorgs) where the longest chain changes, difficulty adjustment every 2016 blocks, and the transition between different block header formats. If the light client does not handle these correctly, an attacker can feed it a fake chain with lower difficulty, perform a long-range attack with headers that do not follow difficulty adjustment rules, or exploit a reorg to revert confirmed staking or slashing transactions.

Identify

1. Find the Bitcoin light client implementation on the PoS chain — locate the block header storage, header validation logic, and chain selection algorithm.
2. Search for reorg handling — how does the light client handle a competing chain that has more proof-of-work than the currently accepted chain?
3. Locate the difficulty adjustment implementation — verify that the light client validates difficulty transitions every 2016 blocks according to Bitcoin's adjustment algorithm.

Analyze

1. Verify that the light client follows the "most cumulative proof-of-work" chain selection rule — it should accept a fork with more total work even if it means reverting recently accepted headers.
2. Check that difficulty adjustment is validated correctly: every 2016 blocks, the new difficulty target is computed from the time span of the previous 2016 blocks, with bounds (no more than 4x increase or 4x decrease).
3. Verify that the light client requires sufficient confirmation depth before considering Bitcoin transactions final — reorgs of 1-6 blocks are common, and the light client should wait for sufficient confirmations before accepting staking or slashing transactions as final.

Exploitability

1. An attacker mines a fake Bitcoin chain with artificially low difficulty (possible if the light client does not validate difficulty adjustments) and submits it to the PoS chain — the fake chain can include staking transactions that do not exist on the real Bitcoin chain, granting the attacker phantom staking power.
2. A Bitcoin reorg that reverts a confirmed staking transaction causes the PoS chain to grant staking power based on a transaction that no longer exists — the staker can equivocate without staked BTC at risk (the staking transaction was reverted).
3. A long-range attack using pre-computed headers that skip difficulty adjustment validation can create a convincing but invalid chain that the light client accepts, overriding the real Bitcoin chain state.

Check

1. Implement full difficulty adjustment validation in the light client — reject any chain where difficulty transitions do not follow Bitcoin's algorithm.
2. Require a confirmation depth of at least 6 blocks (and preferably more for high-value staking) before accepting Bitcoin transactions as final on the PoS chain.
3. Add tests that submit fake chains with incorrect difficulty adjustments, deep reorgs, and long-range attacks, verifying the light client rejects them.

---

### Title: 0x000e-stake-withdrawal-must-enforce-unbonding-period-even-under-mass-exit-conditions

Description
During a mass exit event (many stakers unbonding simultaneously — e.g., due to a PoS chain crisis, market panic, or protocol vulnerability disclosure), the unbonding period must remain enforced for all stakers. If the protocol allows accelerated withdrawal under mass exit conditions (e.g., reducing the timelock to accommodate high demand) or if the unbonding queue overflows, validators can exploit the chaos to equivocate and withdraw before slashing.

Identify

1. Find the unbonding queue or withdrawal processing logic — determine how the protocol handles multiple simultaneous unbonding requests.
2. Search for any mass exit handling or emergency withdrawal mechanisms — does the protocol have special rules for high-volume unbonding?
3. Locate timelock enforcement under stress conditions — is the unbonding period maintained regardless of how many stakers are unbonding?

Analyze

1. Verify that the unbonding timelock is enforced at the Bitcoin Script level (not just application level) for every individual staker — Script-level enforcement cannot be overridden by the protocol during mass exit.
2. Check that the unbonding queue does not have a maximum capacity that, when exceeded, triggers alternative processing (e.g., skipping the timelock or batch-processing withdrawals).
3. Verify that the protocol does not reduce the unbonding period dynamically based on exit demand — the timelock must be constant for each staking position (set at staking time, immutable afterward).

Exploitability

1. An attacker triggers a mass exit event (e.g., by spreading FUD about the PoS chain's security), then equivocates while the slashing evidence pipeline is overwhelmed by the volume of unbonding transactions — the attacker's unbonding transaction processes before the slashing transaction.
2. A protocol that reduces the unbonding period during mass exit to improve user experience inadvertently shortens the slashing window, allowing equivocating validators to escape punishment.
3. An unbonding queue overflow that causes the protocol to process withdrawals out of order can prioritize the attacker's withdrawal over the slashing transaction.

Check

1. Enforce unbonding timelocks at the Bitcoin Script level using `OP_CSV` — this is immutable once the staking transaction is confirmed, regardless of protocol-level queue management.
2. Implement unbonding queue processing that preserves FIFO ordering and does not skip or accelerate any position under any conditions.
3. Add tests that simulate mass exit (e.g., 100 stakers unbonding simultaneously) while one staker equivocates, verifying that the slashing transaction still executes before the equivocating staker's unbonding completes.

---

### Title: 0x000f-protocol-upgrade-must-not-strand-or-make-unspendable-existing-staked-utxos

Description
BTC staking protocols will need to upgrade over time — changing parameters, fixing bugs, adding features, or migrating to new cryptographic primitives. Protocol upgrades must handle existing staked UTXOs carefully: if the upgrade changes the spending conditions, script structure, or covenant format in a way that is incompatible with existing staked UTXOs, those UTXOs can become unspendable — the staker's BTC is permanently locked.

Identify

1. Find the protocol upgrade mechanism — locate how the staking protocol updates its parameters, scripts, or covenant structure.
2. Search for backward compatibility handling — does the upgrade path maintain support for existing staked UTXOs that were created under the old protocol version?
3. Locate migration procedures — is there a defined process for moving staked BTC from old-format covenants to new-format covenants?

Analyze

1. Verify that existing staked UTXOs remain spendable after the protocol upgrade — the pre-signed transactions created under the old protocol must remain valid on the Bitcoin network after the upgrade.
2. Check that the upgrade does not change the interpretation of existing Tapscript leaves or UTXO scripts — Script semantics are enforced by Bitcoin consensus and cannot be "upgraded" for existing UTXOs.
3. Verify that the migration path (if moving from old format to new format) does not require the staker to be online or to take action within a specific timeframe — offline stakers should not lose their BTC because they missed a migration window.

Exploitability

1. A protocol upgrade that changes the slashing transaction format makes old slashing transactions invalid — validators staked under the old protocol can equivocate without risk of slashing.
2. A migration mechanism that requires the staker's online participation within a deadline (e.g., "re-stake under the new format within 30 days") can cause permanent loss of BTC for stakers who are offline, on vacation, or incapacitated.
3. A protocol upgrade that changes the burn address for slashing transactions can inadvertently make old slashing transactions send funds to a recoverable address — the validator can equivocate and recover the "slashed" funds.

Check

1. Maintain backward compatibility for existing staked UTXOs — old pre-signed transactions must remain valid after protocol upgrades.
2. Implement non-interactive migration: if existing stakers must move to a new format, provide a generous timelock-based fallback that automatically handles migration without requiring staker action.
3. Add tests that simulate a protocol upgrade while staked UTXOs exist under the old format, verifying that unbonding, slashing, and withdrawal remain functional for old-format staking positions.
