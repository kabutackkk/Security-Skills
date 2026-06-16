---
name: audit-psbt-security
description: Audits PSBT construction, signing, and finalization flows for sighash misuse, input/output injection, UTXO verification failures, fee manipulation, Taproot trust model confusion, MuSig2 nonce safety violations, and finalization integrity gaps. Produces a findings.md report with ranked vulnerabilities.
when_to_use: |
  Use when user mentions "PSBT", "partially signed bitcoin transaction", "BIP-174", "BIP-370", "bitcoin signing", "sighash", "MuSig2", "Taproot signing", "multisig bitcoin", "bitcoin wallet audit", "bitcoinjs-lib", "@scure/btc-signer", "tiny-secp256k1", "ecpair", "Psbt.fromBase64", "psbt.signInput", "psbt.finalizeAllInputs" or asks about PSBT best practices, vulnerabilities, or audit requirements.
  Do NOT use for Lightning-specific payment channel logic (use audit-ln-dapp-general) or Clarity contracts.
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

# PSBT Security Vulnerability Scanner

## 1. Introduction

Partially Signed Bitcoin Transactions (PSBTs) defined in BIP-174 and extended by BIP-370 (PSBTv2) provide a standardized format for constructing, passing, and signing Bitcoin transactions across trust boundaries. This format is the backbone of hardware wallet communication, multi-party signing protocols, marketplace order books, BRC-20/Ordinals trading, and BTC staking infrastructure. Security failures in PSBT handling have led to real-world fund losses including the 2020 Trezor/Ledger fee overpayment attack, BRC-20 snipping attacks documented in 2024 academic research, and multiple SIGHASH_SINGLE index overflow exploits in Bitcoin's history.

PSBT security extends far beyond signature correctness. The transaction construction pipeline—from UTXO selection through sighash commitment, multi-party signing rounds, and finalization—presents a wide attack surface. Each stage introduces distinct vulnerability classes: sighash flag misuse can silently grant attackers output or input modification rights, UTXO metadata spoofing can trick signers into overpaying fees by orders of magnitude, and incomplete finalization checks can broadcast transactions with missing or invalid signatures. In multi-party contexts such as MuSig2 (BIP-327) or threshold schemes, nonce management failures are catastrophic—a single nonce reuse algebraically reveals the private key.

This skill covers BIP-174 (PSBTv0), BIP-370 (PSBTv2), BIP-341/342 (Taproot/Tapscript), BIP-340 (Schnorr signatures), and BIP-327 (MuSig2). It targets auditors reviewing Bitcoin-native code including wallet implementations, marketplace backends, signing coordinators, and any system that constructs, parses, signs, or finalizes PSBTs. All pseudocode examples use Bitcoin Script semantics and transaction structure rather than EVM/Solidity conventions.

---

## 2. Purpose

This skill audits PSBT construction, signing, and finalization flows to detect sighash misuse, input/output injection, UTXO verification failures, fee manipulation, Taproot trust model confusion, MuSig2 nonce safety violations, and finalization integrity gaps.

---

## 3. When to Use This Skill

**Prompt trigger**

```
Does the code construct, parse, sign, or finalize PSBTs? ──yes──> Use this skill
│
no
│
v
Does it implement Bitcoin signing logic (sighash, scriptSig, witness)? ──yes──> Use this skill
│
no
│
v
Does it handle multi-party Bitcoin signing (MuSig2, threshold, multisig)? ──yes──> Use this skill
│
no
│
v
Does it process Taproot key tweaking, script trees, or BIP-340 signatures? ──yes──> Use this skill
│
no
│
v
Does it manage UTXO selection, fee calculation, or change output logic for Bitcoin? ──yes──> Use this skill
│
no
│
v
Skip this skill
```

**Concrete triggers**

- PSBT creation, parsing, or serialization (`Psbt`, `CreatePsbt`, `DecodePsbt`, `PSBT_GLOBAL_UNSIGNED_TX`)
- Sighash flag usage (`SIGHASH_ALL`, `SIGHASH_NONE`, `SIGHASH_SINGLE`, `SIGHASH_ANYONECANPAY`, `SIGHASH_DEFAULT`)
- Input signing and witness construction (`SignInput`, `WitnessUtxo`, `NonWitnessUtxo`, `FinalScriptSig`, `FinalScriptWitness`)
- Taproot fields (`TAP_KEY_SIG`, `TAP_SCRIPT_SIG`, `TAP_LEAF_SCRIPT`, `TAP_INTERNAL_KEY`, `TAP_MERKLE_ROOT`)
- MuSig2 operations (`MuSig2NonceGen`, `MuSig2NonceAgg`, `MuSig2Sign`, `MuSig2PartialSigAgg`)
- UTXO handling (`utxo.value`, `prevout`, `scriptPubKey`, change address derivation)
- Fee calculation and validation (`fee = sum(inputs) - sum(outputs)`, fee rate bounds)
- Multi-party coordination (signing rounds, partial signature collection, PSBT merging via `CombinePsbt`)
- BIP-174/BIP-370 field access (`PSBT_IN_*`, `PSBT_OUT_*`, global/input/output maps)
- Transaction finalization and broadcast (`FinalizePsbt`, `ExtractTransaction`, `sendrawtransaction`)
- TypeScript SDK: `import * as bitcoin from "bitcoinjs-lib"`, `import { Psbt } from "bitcoinjs-lib"`
- TypeScript SDK: `psbt.signInput`, `psbt.addInput`, `psbt.finalizeAllInputs`, `psbt.extractTransaction`
- TypeScript SDK: `import * as ecc from "tiny-secp256k1"`, `ECPairFactory`, `BIP32Factory`
- TypeScript SDK: `@scure/btc-signer`, `@noble/secp256k1`, `bip174`
- TypeScript SDK: `sighashType`, `witnessUtxo`, `nonWitnessUtxo`, `tapInternalKey`

## Additional resources

- For real-world TypeScript vulnerable patterns using `bitcoinjs-lib` and `@scure/btc-signer`, see [typescript-vulnerable-patterns.md](references/typescript-vulnerable-patterns.md)

---

## Goal

Produce a `findings.md` file containing all identified vulnerabilities in the target PSBT handling code, each with a title, code location, description, attack scenario, and fix recommendation. Every checkpoint in the checklist below must be evaluated. The audit is complete when all checkpoints have been checked and all findings are reported.

## Workflow

### Step 1: Establish scope
Identify the target files and modules that construct, parse, sign, or finalize PSBTs. Confirm the project handles Bitcoin transactions and matches this skill's domain.

**Artifacts**: list of target files, confirmed project type
**Success criteria**: The target file set is known and confirmed to involve PSBT handling.

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

### Title: 0x0000-sighash-none-must-not-allow-unrestricted-output-modification

Description
`SIGHASH_NONE` commits to no outputs, allowing anyone who sees the signed input to attach arbitrary outputs and redirect all funds. This flag is almost never appropriate and its presence in signing code is a critical red flag.

Identify

1. Search for sighash flag assignment in signing functions—look for `SIGHASH_NONE` (byte `0x02`), sighash parameter defaults, and any user-controllable sighash selection.
2. Locate PSBT input records where `PSBT_IN_SIGHASH_TYPE` is set or where the sighash byte is embedded in the signature suffix.

Analyze

1. Verify that `SIGHASH_NONE` is never used unless there is an explicit, documented, and architecturally justified reason (extremely rare—e.g., a specific multi-party protocol step where the signer intentionally defers output choice).
2. Check whether the sighash flag can be downgraded by an intermediary between PSBT construction and signing (e.g., a coordinator replacing `SIGHASH_ALL` with `SIGHASH_NONE` in the PSBT before passing to a hardware wallet).
3. Verify that sighash validation occurs on the signing device or library, not only on the coordinator side.

Exploitability

1. An attacker who obtains a `SIGHASH_NONE`-signed input can construct a new transaction reusing that input with outputs sending all funds to their own address, since the signature commits to zero outputs.
2. In a marketplace or multi-party context, a counterparty can replace all outputs after receiving the victim's `SIGHASH_NONE` signature, stealing the victim's UTXO entirely.

Check

1. Reject `SIGHASH_NONE` at the signing layer unless explicitly allowlisted per protocol specification with documented security justification.
2. Implement sighash flag validation before signing—verify the flag matches the expected commitment level for the transaction type.
3. Add tests that attempt to modify outputs after signing with `SIGHASH_NONE` and confirm the system rejects or never produces such signatures.

---

### Title: 0x0001-sighash-single-index-mismatch-must-not-create-anyone-can-spend-outputs

Description
`SIGHASH_SINGLE` commits the signature to the output at the same index as the input being signed. When the input index exceeds the number of outputs, Bitcoin's historical behavior returns a hash of `uint256(1)` instead of a proper sighash digest—a known, fixed value that produces an anyone-can-spend condition. This is the "SIGHASH_SINGLE bug" present in Bitcoin's consensus rules.

Identify

1. Find all uses of `SIGHASH_SINGLE` (byte `0x03`) in signing paths and verify the relationship between input indices and output count.
2. Locate transaction construction logic that adds inputs and outputs in separate steps where the index relationship can become inconsistent.

Analyze

1. Verify that for every input signed with `SIGHASH_SINGLE`, a corresponding output at the same index exists at signing time and cannot be removed before broadcast.
2. Check that transaction building code enforces `input_index < len(outputs)` as a precondition before signing with `SIGHASH_SINGLE`.
3. Review whether PSBT merging or combining operations can alter the output array after a `SIGHASH_SINGLE` signature is attached.

Exploitability

1. If input index `i` has no matching output `i`, the sighash resolves to `uint256(1)`—a known constant. Anyone can compute a valid signature for this hash, making the input spendable by any party who recognizes the condition.
2. An attacker in a multi-party PSBT workflow can manipulate output ordering or remove outputs to trigger the index mismatch, then spend the resulting anyone-can-spend input.

Check

1. Enforce strict index parity validation: reject signing any input with `SIGHASH_SINGLE` when `input_index >= len(outputs)`.
2. Lock the output array before any `SIGHASH_SINGLE` signing begins and reject subsequent modifications.
3. Add tests that attempt to sign inputs at indices beyond the output array and confirm the signing library rejects the operation.

---

### Title: 0x0002-sighash-anyonecanpay-combined-flags-must-not-permit-unintended-manipulation

Description
`SIGHASH_ANYONECANPAY` (byte `0x80`) can be combined with `ALL`, `NONE`, or `SINGLE`, producing three distinct commitment levels. Each combination grants different modification rights to other parties. Misunderstanding these combinations—especially `ANYONECANPAY|NONE` (commits to nothing) or `ANYONECANPAY|SINGLE` (commits to one output, no other inputs)—can expose transactions to input injection and output manipulation.

Identify

1. Find all locations where `SIGHASH_ANYONECANPAY` is combined with other flags (byte values `0x81`, `0x82`, `0x83`) and map which combination is used in each signing context.
2. Locate protocol documentation or comments describing the intended modification rights for each signer and verify they match the actual sighash combination used.

Analyze

1. For `ANYONECANPAY|ALL` (`0x81`): verify the protocol intends to allow additional inputs from other parties while keeping all outputs fixed—common in crowdfunding/pledge patterns.
2. For `ANYONECANPAY|NONE` (`0x82`): verify this extreme combination is genuinely intended—it commits to no inputs (except the signed one) and no outputs, granting near-total modification rights to anyone.
3. For `ANYONECANPAY|SINGLE` (`0x83`): verify the index-matched output constraint is maintained and that the protocol expects additional inputs and unmatched outputs to be modifiable.
4. Check that the combination selection cannot be influenced by untrusted input (e.g., a server choosing the sighash for a client's signing operation).

Exploitability

1. `ANYONECANPAY|NONE` allows any party to add inputs and replace all outputs—effectively granting full control over the transaction's economic outcome to whoever finalizes it.
2. `ANYONECANPAY|SINGLE` with a mismatched index inherits the `SIGHASH_SINGLE` bug (checkpoint 0x0001) while also allowing input injection, compounding the attack surface.
3. A marketplace coordinator using `ANYONECANPAY` combinations can inject additional inputs from the seller to steal more UTXOs than the seller intended to spend.

Check

1. Document and enforce the exact intended modification rights for each sighash combination used in the protocol.
2. Require explicit allowlisting of each sighash combination per transaction type—reject unexpected combinations at signing time.
3. Add tests that exercise each modification right granted by the sighash combination: inject inputs, replace outputs, reorder outputs, and verify the system rejects unauthorized modifications.

---

### Title: 0x0003-psbt-inputs-must-not-be-injectable-before-finalization

Description
Between PSBT creation and finalization, malicious participants or compromised coordinators can inject additional inputs into the PSBT. If signers do not validate the full input set, they may sign a transaction spending UTXOs they did not intend to spend—effectively authorizing theft of their own funds.

Identify

1. Find the PSBT construction flow from initial creation through each signing round to finalization, and identify every point where inputs can be added or modified.
2. Locate the validation logic that signers apply before signing—determine whether each signer verifies the complete input set or only their own input(s).
3. Search for PSBT combining/merging operations (`CombinePsbt`) that might introduce inputs from another party.

Analyze

1. Verify that each signer inspects and approves the complete list of inputs (not just their own) before producing a signature, or that the sighash type used commits to the full input set.
2. Check that PSBT round-trip operations (serialize → deserialize → modify → re-serialize) cannot silently add inputs without detection.
3. Verify that the coordinator or any intermediary cannot add inputs between collecting signatures from different parties.

Exploitability

1. A malicious coordinator adds the victim's additional UTXOs as new inputs to the PSBT, then requests the victim to sign. If the victim signs with `SIGHASH_ANYONECANPAY` or only inspects their expected input, the coordinator obtains signatures covering the additional UTXOs.
2. In a marketplace context, the platform can inject a seller's high-value UTXO into a small trade PSBT, obtaining a valid signature over both the trade input and the injected input.

Check

1. Implement full input set validation at the signing layer: present all inputs (with amounts and scriptPubKeys) to the signer for approval.
2. On hardware wallets or secure signing environments, display the total input value and all input UTXOs before requesting signature confirmation.
3. Add tests that inject additional inputs between PSBT creation and signing, and confirm the signer rejects the modified PSBT.

---

### Title: 0x0004-psbt-outputs-and-change-must-be-immutable-after-first-signature

Description
Output modification after the first signature is attached can redirect funds without the first signer's knowledge. Change output manipulation is particularly dangerous because change addresses are often auto-generated and may not receive the same scrutiny as primary outputs.

Identify

1. Find the output construction and change address derivation logic in the PSBT builder.
2. Locate where outputs are finalized relative to when the first signature is collected.
3. Search for any code paths that modify, reorder, or add outputs after at least one valid signature exists on the PSBT.

Analyze

1. Verify that the output set (including change) is immutable once the first signature using `SIGHASH_ALL` is attached.
2. Check that change address derivation uses a verified derivation path and the change output amount is computed as `sum(inputs) - sum(payment_outputs) - fee` with no rounding exploits.
3. Verify that no intermediary can substitute the change address between PSBT construction and final signing.

Exploitability

1. A MITM between signers in a multisig setup replaces the change output address with their own address. The first signer approved the original change address, but the second signer signs a modified PSBT—the first signer's `SIGHASH_ALL` signature is now invalid, but if the MITM can get a fresh signature or exploit a `SIGHASH_SINGLE` commitment, funds are stolen.
2. In BRC-20/Ordinals marketplaces, the platform can modify the change output to sweep dust UTXOs containing inscriptions.

Check

1. Lock the output array (including change) before any signing begins and reject modifications after the first signature is attached.
2. Verify change addresses against the signer's own derivation paths—display the full output set including change on the signing device.
3. Add tests that modify outputs (value, scriptPubKey, or order) between signing rounds in a multi-party PSBT and confirm signature validation fails.

---

### Title: 0x0005-non-witness-utxo-hash-must-be-verified-against-prevout

Description
BIP-174 requires the `PSBT_IN_NON_WITNESS_UTXO` field to contain the full previous transaction for legacy (non-SegWit) inputs. If the signing library does not verify that the hash of this transaction matches the `prevout` txid in the unsigned transaction, an attacker can supply a fake previous transaction with a different output amount, tricking the signer into an incorrect fee calculation.

Identify

1. Find where `PSBT_IN_NON_WITNESS_UTXO` is parsed and how the signing library uses the previous transaction data.
2. Locate the hash verification step: does the library compute `SHA256d(non_witness_utxo)` and compare it to the `prevout.hash` in the corresponding input?
3. Check whether the library falls back to trusting the UTXO data without verification when the hash check is absent or optional.

Analyze

1. Verify that the signing library always computes the double-SHA256 of the serialized non-witness UTXO and rejects the PSBT if it does not match `prevout.hash`.
2. Check that the specific output index (`prevout.n`) is validated within the previous transaction—ensure the index is in bounds and the referenced output exists.
3. Verify this check cannot be bypassed by providing a `PSBT_IN_WITNESS_UTXO` alongside a non-witness input to skip the full transaction verification.

Exploitability

1. An attacker supplies a crafted previous transaction with the same txid structure but a higher output value. The signer computes `fee = sum(input_amounts) - sum(output_amounts)` using the inflated input amount, believing the fee is reasonable, when in reality the true input amount is lower and the actual fee is much higher.
2. This is the precursor to the fee overpayment attack (see checkpoint 0x0006) for legacy inputs.

Check

1. Enforce mandatory hash verification: `SHA256d(non_witness_utxo) == prevout.hash` for every non-witness input before signing.
2. Validate the output index is within bounds of the previous transaction.
3. Add tests that supply a non-witness UTXO with a mismatched hash and confirm the signing library rejects the PSBT.

---

### Title: 0x0006-witness-utxo-amount-must-be-verified-to-prevent-fee-overpayment

Description
The 2020 fee overpayment attack against Trezor and Ledger hardware wallets exploited the fact that SegWit signing only requires `PSBT_IN_WITNESS_UTXO` (a single output record with value and scriptPubKey) rather than the full previous transaction. An attacker can lie about the UTXO amount across multiple signing sessions, tricking the signer into paying excessive fees. This attack works even when each individual signing session appears to have a reasonable fee.

Identify

1. Find where `PSBT_IN_WITNESS_UTXO` is consumed for SegWit input signing and whether the amount is independently verified.
2. Locate whether the signing library or hardware wallet requests the full previous transaction for SegWit inputs as an additional verification step (the mitigation adopted by Trezor/Ledger post-2020).
3. Check for multi-session signing scenarios where the same UTXO might be presented with different amounts across sessions.

Analyze

1. Verify that the signer cross-references the witness UTXO amount against the full previous transaction (if available) or against an independent UTXO set/source.
2. Check that for protocols involving multiple signing rounds or sessions, the UTXO metadata is consistent across all rounds.
3. Verify that the total fee (`sum(input_values) - sum(output_values)`) is displayed to the user and bounded by a configurable maximum before signing proceeds.

Exploitability

1. An attacker creates two PSBTs spending the same UTXO but with different claimed amounts (e.g., 1 BTC in one and 0.5 BTC in another). The signer signs both, each appearing to have a reasonable fee. When one is broadcast, the actual fee paid is the true UTXO amount minus outputs—potentially draining the entire UTXO as fee.
2. A compromised software wallet can systematically inflate witness UTXO amounts to make excessive fees appear normal, slowly draining user funds to miners (potentially colluding miners).

Check

1. Require the full previous transaction for witness inputs and verify `SHA256d(prev_tx).output[n].value == witness_utxo.value`.
2. Enforce per-transaction and per-session fee bounds—reject signing if the calculated fee exceeds a configurable maximum (e.g., 10% of total input value or an absolute satoshi limit).
3. Add tests that present the same UTXO with different amounts across signing sessions and confirm the signer detects the inconsistency.

---

### Title: 0x0007-script-type-in-utxo-must-match-signing-derivation-path-and-redeem-script

Description
A mismatch between the UTXO's scriptPubKey type (P2PKH, P2SH, P2WPKH, P2WSH, P2TR) and the signing derivation path or redeem/witness script can cause signature failures, fund loss, or security bypasses. Attackers can supply a UTXO with a different script type to confuse the signer into using the wrong signing algorithm.

Identify

1. Find where the signing library determines the script type from the UTXO's scriptPubKey and selects the corresponding signing algorithm (ECDSA vs Schnorr, legacy vs SegWit sighash).
2. Locate BIP-32 derivation path validation—check whether the path purpose field (44'/49'/84'/86') is verified against the script type.
3. Search for `PSBT_IN_REDEEM_SCRIPT` and `PSBT_IN_WITNESS_SCRIPT` handling and whether these are validated against the UTXO's scriptPubKey.

Analyze

1. Verify that the script type derived from the UTXO matches the expected type based on the derivation path and that the signing algorithm is selected accordingly.
2. Check that for P2SH-wrapped inputs, the redeemScript hashes to the script hash in the scriptPubKey (`HASH160(redeemScript) == scriptPubKey[2:22]`).
3. For P2WSH inputs, verify that the witnessScript SHA256 matches the witness program (`SHA256(witnessScript) == witness_program`).
4. Verify that Taproot inputs (P2TR) use Schnorr signing (BIP-340) and legacy inputs use ECDSA—no cross-contamination.

Exploitability

1. Supplying a P2TR scriptPubKey with a legacy derivation path can cause the signer to use ECDSA instead of Schnorr, producing an invalid signature—or worse, if the library falls through to a different code path, it may sign with incorrect sighash computation.
2. A crafted redeemScript that hashes correctly but contains unexpected opcodes (e.g., `OP_TRUE`) can make any signature valid, allowing fund theft if the signer does not inspect the script content.

Check

1. Validate script type consistency: UTXO scriptPubKey type must match derivation path purpose, signing algorithm, and any provided redeem/witness scripts.
2. Verify redeem and witness script hash commitments against the scriptPubKey before signing.
3. Add tests that supply mismatched script types (e.g., P2TR UTXO with P2WPKH derivation path) and confirm the signing library rejects the input.

---

### Title: 0x0008-psbt-fee-must-be-bounded-to-prevent-fee-sniping-and-escalation-attacks

Description
Unbounded fees enable direct value extraction from signers. In BRC-20 and Ordinals marketplaces, fee manipulation is a primary attack vector: attackers construct PSBTs with inflated fees so that the excess fee value is captured by colluding miners, or they manipulate the fee to make competing transactions uneconomical.

Identify

1. Find fee calculation logic: `fee = sum(input_amounts) - sum(output_amounts)` and any fee rate computation (`fee / vbytes`).
2. Locate fee validation bounds—maximum absolute fee, maximum fee rate (sat/vB), and maximum fee as a percentage of transaction value.
3. Search for user-facing fee display and confirmation flows.

Analyze

1. Verify that fee bounds are enforced before signing and are not bypassable by the transaction constructor or coordinator.
2. Check that fee rate calculations use accurate virtual size (vbytes) accounting for SegWit discount and Taproot witness size.
3. Verify that the system prevents fee escalation attacks where a sequence of transactions with incrementally increasing fees drains the user's UTXOs.

Exploitability

1. A marketplace constructs a PSBT where the "price" output goes to the seller but the fee is set to consume most of the buyer's input UTXO. The buyer sees a correct price but does not notice the excessive fee, which goes to a colluding miner.
2. BRC-20 snipping attacks use fee manipulation to front-run inscription transactions: the attacker creates a higher-fee replacement transaction that captures the inscription transfer intended for the victim.
3. Fee escalation via RBF (Replace-By-Fee): an attacker repeatedly bumps the fee on a shared PSBT, each bump consuming more of the victim's input value.

Check

1. Enforce configurable fee bounds: maximum absolute fee, maximum fee rate (sat/vB), and maximum fee-to-value ratio.
2. Display the exact fee amount and fee rate to the signer before requesting signature confirmation.
3. Add tests that construct PSBTs with excessive fees (absolute and rate-based) and confirm the system rejects signing.

---

### Title: 0x0009-mempool-exposure-of-partial-psbt-must-not-enable-front-running-or-replacement

Description
Partial or complete PSBTs that reach the public mempool or are visible to intermediaries before all parties have signed create front-running and transaction replacement opportunities. In marketplace contexts, this enables snipping attacks where an attacker replaces the victim's pending transaction with one that redirects the valuable asset.

Identify

1. Find where partially signed or fully signed transactions are transmitted—search for mempool submission, relay to coordinators, or broadcast APIs.
2. Locate RBF (BIP-125) signaling: check `nSequence` values on inputs (`< 0xFFFFFFFE` signals RBF) and whether the transaction opts into replacement.
3. Search for time-sensitive signing protocols where the window between partial and full signing creates an exploit opportunity.

Analyze

1. Verify that partially signed transactions are never broadcast or leaked to untrusted parties before all required signatures are collected.
2. Check whether RBF is intentionally enabled and, if so, whether the protocol accounts for replacement attacks.
3. Verify that the PSBT exchange protocol uses authenticated, encrypted channels between signers—not public or semi-public relay mechanisms.

Exploitability

1. An attacker monitoring the mempool or the PSBT relay channel sees a partially signed marketplace transaction. They construct a competing transaction spending the same seller input with a higher fee, redirecting the asset to themselves (snipping attack).
2. With RBF enabled, an attacker who has one valid signature can replace the pending transaction with a version that has modified outputs before the second signer has signed, effectively front-running the original intent.
3. Mempool observation of PSBT exchange patterns can reveal trading intent, enabling sandwich attacks on BRC-20/Ordinals trades.

Check

1. Never broadcast partially signed transactions—complete all signing rounds before submission to the Bitcoin network.
2. If RBF is required, implement explicit replacement protections: pin the transaction with CPFP or use `nSequence = 0xFFFFFFFE` to disable RBF where replacement is not needed.
3. Use authenticated, encrypted communication channels for PSBT exchange between signers.
4. Add tests that simulate mempool observation and replacement attempts, confirming the protocol is resistant to snipping and front-running.

---

### Title: 0x000a-taproot-key-path-vs-script-path-trust-model-must-be-explicitly-verified

Description
Taproot outputs (P2TR, BIP-341) support two spending paths: the key path (a single Schnorr signature on the tweaked output key) and the script path (revealing a Tapscript leaf from the MAST tree). These paths have fundamentally different trust models: the key path holder can spend unilaterally without revealing any script conditions, while script path spending requires satisfying a specific Tapscript. Confusion between these paths can bypass intended spending conditions.

Identify

1. Find Taproot output construction: locate where the internal key, Tapscript tree, and output key tweak are computed.
2. Identify which spending path(s) the protocol intends to use and whether key path spending is intentionally enabled or should be disabled.
3. Locate signing logic that selects between key path (`TAP_KEY_SIG`) and script path (`TAP_SCRIPT_SIG`) signing.

Analyze

1. Verify that if the protocol relies on script path conditions (timelocks, hash locks, multisig leaves) for security, the key path cannot bypass these conditions.
2. Check whether the internal key is a known, controlled key or an unspendable point (e.g., NUMS point `H` with no known discrete log) when key path spending should be disabled.
3. Verify that the Tapscript tree structure matches the intended spending policies and no unauthorized leaves are included.
4. Check that BIP-370 Taproot-specific fields (`PSBT_IN_TAP_KEY_SIG`, `PSBT_IN_TAP_SCRIPT_SIG`, `PSBT_IN_TAP_LEAF_SCRIPT`, `PSBT_IN_TAP_INTERNAL_KEY`, `PSBT_IN_TAP_MERKLE_ROOT`) are set correctly and consistently.

Exploitability

1. If the internal key is a single party's public key in a protocol that requires multisig authorization via script path, that single party can bypass the multisig requirement by spending via key path.
2. A malicious coordinator can construct a Taproot output with their own key as the internal key while telling other parties the output uses a multisig Tapscript—the coordinator can then unilaterally spend via key path at any time.
3. Including a hidden Tapscript leaf (e.g., `OP_TRUE`) in the MAST tree creates a backdoor spending path that other parties may not detect if they do not verify the full tree.

Check

1. Explicitly document and enforce the intended trust model: if key path should be disabled, use an unspendable internal key (NUMS point).
2. Verify the complete Tapscript tree against the protocol specification—ensure no unauthorized leaves exist.
3. Require signers to verify `PSBT_IN_TAP_INTERNAL_KEY` and `PSBT_IN_TAP_MERKLE_ROOT` before signing.
4. Add tests that attempt key path spending on outputs intended for script-path-only use and confirm the key path is not available.

---

### Title: 0x000b-taproot-output-key-tweak-and-bip370-fields-must-be-validated-before-signing

Description
The Taproot output key is derived by tweaking the internal key with the Tapscript tree root: `Q = P + H(P || merkle_root) * G`. If the tweak is computed incorrectly, validated insufficiently, or the BIP-370 PSBT fields are inconsistent, signers may produce signatures for a different output than intended—or the tweak can be poisoned to create an output spendable by the attacker.

Identify

1. Find the output key tweak computation: `tweak = tagged_hash("TapTweak", P || merkle_root)` and `Q = P + tweak * G`.
2. Locate where `PSBT_IN_TAP_INTERNAL_KEY`, `PSBT_IN_TAP_MERKLE_ROOT`, and `PSBT_OUT_TAP_INTERNAL_KEY` are populated and consumed.
3. Search for parity bit handling in the tweaked key and signature serialization.

Analyze

1. Verify that the tweak is computed using the correct tagged hash (`"TapTweak"`) with the exact serialization specified in BIP-341.
2. Check that the internal key `P` in the PSBT matches the signer's expected key and is not substituted by a coordinator.
3. Verify that the merkle root in the PSBT corresponds to the expected Tapscript tree—recompute the tree hash from the leaf scripts and compare.
4. Check parity bit handling: the output key must have even y-coordinate, and if the internal key's y is odd, the signer must negate the private key before tweaking.

Exploitability

1. A malicious coordinator supplies a different internal key (their own) in the PSBT while the output on-chain uses the victim's key tweaked with the correct merkle root. The victim signs for the wrong key—their signature is invalid, and the coordinator can produce a valid signature using their own key.
2. Tweak poisoning: the coordinator manipulates the merkle root to change the tweak value so that the output key `Q` is actually `coordinator_key + tweak' * G`, giving the coordinator key-path spending ability.
3. Incorrect parity handling produces invalid Schnorr signatures, causing transaction rejection and potential fund lockup in time-sensitive protocols.

Check

1. Independently recompute the output key tweak from the internal key and merkle root before signing—reject the PSBT if the computed output key does not match the output scriptPubKey.
2. Verify the internal key belongs to the expected signer or multisig group.
3. Validate parity bit handling per BIP-341 section on key generation.
4. Add tests with incorrect tweaks, swapped internal keys, and wrong parity bits to confirm the signing library rejects invalid Taproot parameters.

---

### Title: 0x000c-musig2-nonce-must-never-be-reused-across-signing-sessions

Description
MuSig2 (BIP-327) is a Schnorr-based multi-signature scheme where each signer generates a secret nonce pair for each signing session. If a signer reuses the same nonce across two different signing sessions (even for the same message), the algebraic structure of Schnorr signatures allows any other participant to extract the signer's private key. This is not a theoretical risk—it is a deterministic algebraic extraction with zero computational cost.

Identify

1. Find MuSig2 nonce generation: locate `NonceGen` calls and verify that each invocation produces fresh randomness.
2. Search for nonce storage and lifecycle management—determine where nonces are persisted and how used nonces are invalidated.
3. Locate signing session state management and check whether nonces are bound to specific sessions.

Analyze

1. Verify that nonce generation uses a CSPRNG (cryptographically secure pseudorandom number generator) and that the output is never deterministic based solely on the message or public data.
2. Check that nonces are generated fresh for every signing session and are destroyed immediately after use (one-time use guarantee).
3. Verify that session state isolation prevents nonce values from leaking across sessions—e.g., concurrent signing sessions must use independent nonces.
4. Check for error recovery paths where a failed signing session might retry with the same nonce.

Exploitability

1. Given two Schnorr partial signatures `s1 = r + e1 * x` and `s2 = r + e2 * x` using the same nonce `r` but different challenges `e1, e2`, the private key is extracted as `x = (s1 - s2) / (e1 - e2)`. This requires zero brute force—it is simple field arithmetic.
2. A malicious co-signer can trigger nonce reuse by aborting the first signing session after receiving the victim's nonce commitment and then initiating a new session. If the victim's implementation reuses the nonce, the attacker obtains two partial signatures with the same nonce.
3. Deterministic nonce generation (à la RFC 6979) is NOT safe for MuSig2 because a co-signer can influence the message, causing the same nonce to be generated for different signing sessions—BIP-327 explicitly requires randomized nonce generation.

Check

1. Verify nonce generation uses fresh randomness (CSPRNG) for every signing session—never derive nonces deterministically from the message alone.
2. Implement nonce use-once enforcement: store nonce state and mark nonces as consumed immediately upon use; reject any attempt to reuse a consumed nonce.
3. Destroy nonce material after signing completes (or fails)—do not persist nonces across session boundaries.
4. Add tests that attempt to reuse nonces across sessions and confirm the implementation rejects the second signing attempt.

---

### Title: 0x000d-musig2-partial-signatures-must-be-validated-before-aggregation

Description
In MuSig2, each signer produces a partial signature that is aggregated into the final Schnorr signature. If partial signatures are not validated before aggregation, a malicious signer can submit an invalid partial signature that, when combined, produces a valid-looking aggregate signature on a different message than what honest signers intended—this is the rogue-key attack variant for multi-signatures.

Identify

1. Find the partial signature aggregation step: locate where partial signatures from multiple signers are combined into the final signature.
2. Search for partial signature verification: does the aggregator verify each partial signature against the signer's public nonce and public key before aggregation?
3. Locate the key aggregation step and check whether proof-of-possession or key coefficient computation (BIP-327 `KeyAgg`) is correctly implemented.

Analyze

1. Verify that each partial signature `s_i` is validated against the signer's committed public nonce `R_i` and their contribution to the aggregate key before being accepted for aggregation.
2. Check that the BIP-327 `KeyAgg` coefficient computation is correctly applied—this prevents rogue-key attacks where a malicious signer chooses their public key as a function of other signers' keys.
3. Verify that the nonce aggregation (`NonceAgg`) correctly combines all signers' public nonces and that the aggregate nonce is used consistently in both signing and verification.

Exploitability

1. Without partial signature validation, a malicious signer can compute their partial signature as a function of the other signers' partial signatures to force the aggregate signature to be valid on a message of the attacker's choice.
2. Without proper key aggregation coefficients, a signer can choose their public key as `X_rogue = X_target - X_honest`, causing the aggregate key to equal `X_target`—a key the attacker controls alone.
3. A compromised aggregation server that does not validate partial signatures can produce fraudulent aggregate signatures that appear valid to external verifiers.

Check

1. Validate every partial signature before aggregation using BIP-327 `PartialSigVerify`.
2. Implement correct `KeyAgg` with key coefficients per BIP-327 to prevent rogue-key attacks.
3. Verify nonce commitment consistency: each signer's public nonce must match their committed value from the first round.
4. Add tests with deliberately invalid partial signatures and rogue keys to confirm the aggregator rejects them.

---

### Title: 0x000e-multi-party-signing-session-state-must-be-isolated-and-tamper-proof

Description
Multi-party signing protocols (MuSig2, threshold FROST, multisig PSBT rounds) maintain session state across multiple communication rounds. If session state is shared, mutable by untrusted parties, or insufficiently isolated between concurrent sessions, attackers can manipulate the protocol to extract keys, forge signatures, or cause signing failures.

Identify

1. Find the session state structure for multi-party signing: nonce commitments, partial nonces, received partial signatures, session identifiers, and participant lists.
2. Locate how concurrent signing sessions are isolated—search for session IDs, separate storage namespaces, or per-session data structures.
3. Search for session state persistence across process restarts, network interruptions, or retry logic.

Analyze

1. Verify that each signing session has a unique, unguessable session identifier and that all protocol messages are bound to this session ID.
2. Check that session state is stored in tamper-proof storage (e.g., memory-only with no serialization to disk, or encrypted at rest if persistence is required).
3. Verify that concurrent sessions cannot read or write each other's state—no shared mutable data structures.
4. Check session timeout and cleanup: stale sessions must be invalidated and their nonce material destroyed.

Exploitability

1. Cross-session state leakage allows an attacker to mix protocol messages from different sessions, potentially causing nonce reuse (see checkpoint 0x000c) or partial signature forgery.
2. A tampered session state (e.g., modified participant list or nonce commitments) can cause honest signers to produce partial signatures that the attacker can combine with their own manipulated contribution to forge the final signature.
3. Persistent session state that survives a crash and is replayed after restart can reintroduce consumed nonces, enabling key extraction.

Check

1. Assign unique, cryptographically random session identifiers and bind all protocol messages to the session ID.
2. Isolate session state in per-session data structures with no shared mutable state between sessions.
3. Implement session timeouts and ensure stale session state (including nonce material) is securely destroyed.
4. Add tests for concurrent session isolation: run parallel signing sessions and verify no cross-contamination of state.

---

### Title: 0x000f-finalization-must-not-proceed-with-missing-or-invalid-signatures

Description
PSBT finalization (`FinalizePsbt`) converts partial signatures and witness data into the final `scriptSig`/`witness` fields and extracts the raw transaction for broadcast. If finalization proceeds with missing signatures, invalid signatures, or incomplete witness data, the broadcast transaction will either fail (wasting fees on-chain) or—in worst cases—create an anyone-can-spend condition if the partial witness satisfies a weaker spending path.

Identify

1. Find the finalization logic: locate `FinalizePsbt` or equivalent that constructs `FinalScriptSig` and `FinalScriptWitness` from PSBT input fields.
2. Check whether finalization validates each signature against the transaction sighash before embedding it in the witness.
3. Search for threshold or multisig finalization that must collect exactly M-of-N signatures and verify the threshold is met.

Analyze

1. Verify that every required signature is present and valid before finalization proceeds—the finalizer must verify each signature against the sighash and public key, not just check for field presence.
2. Check that multisig finalization enforces the correct M-of-N threshold and that the signatures correspond to keys in the multisig script.
3. Verify that finalization correctly handles different script types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR) and constructs the appropriate witness structure for each.
4. Check that the finalizer strips PSBT metadata fields (partial signatures, redeem scripts, derivation paths) from the final transaction—leaking this data is a privacy concern.

Exploitability

1. Premature finalization with only 1-of-2 multisig signatures creates a transaction that will be rejected by the network—but if it reaches a cooperating miner, the miner could potentially add the second signature (if they have access to the second key or if the script has an alternative spending path).
2. Broadcasting a transaction with an invalid signature consumes the input UTXO in a failed transaction if the mempool or miner accepts it, wasting transaction fees and potentially locking funds.
3. Incomplete finalization that leaves PSBT fields in the raw transaction leaks derivation paths, xpubs, and other metadata that deanonymizes the signer.

Check

1. Validate every signature against the computed sighash before constructing the final witness—reject finalization if any signature is missing or invalid.
2. For multisig scripts, verify that exactly M valid signatures from authorized keys are present.
3. Strip all PSBT-specific metadata from the finalized transaction.
4. Add tests that attempt finalization with missing, invalid, or wrong-key signatures and confirm the finalizer rejects the operation.

---

### Title: 0x0010-psbt-deserialization-must-reject-malformed-structures-and-verify-timelocks

Description
PSBT deserialization is a parser that processes untrusted binary data from potentially malicious sources. Malformed PSBTs can exploit parser vulnerabilities (buffer overflows, integer overflows, excessive memory allocation) or contain semantically invalid fields that cause downstream logic errors. Additionally, timelock fields (`nLockTime`, `nSequence`) embedded in the PSBT must be validated to prevent transactions that are time-locked from being finalized prematurely.

Identify

1. Find the PSBT deserialization/parsing code: locate the binary parser that reads the PSBT magic bytes, global fields, and per-input/per-output maps.
2. Search for length field handling: check for integer overflow in key-value pair lengths, maximum size bounds, and duplicate key detection.
3. Locate timelock validation: `nLockTime` in the unsigned transaction and `nSequence` per input, plus any `PSBT_GLOBAL_TX_MODIFIABLE` flags (BIP-370).

Analyze

1. Verify that the parser enforces the PSBT magic bytes (`0x70736274FF`) and rejects data that does not start with the correct header.
2. Check that key-value pair lengths are bounded and that the parser allocates memory safely—no unbounded reads or allocations based on untrusted length fields.
3. Verify that duplicate keys within the same map are rejected (BIP-174 requires key uniqueness per map).
4. Check that `nLockTime` is validated against the current block height or timestamp and that `nSequence` values are consistent with the protocol's timelock requirements.
5. For BIP-370 PSBTv2, verify that `PSBT_GLOBAL_TX_VERSION`, `PSBT_GLOBAL_FALLBACK_LOCKTIME`, and input/output count fields are validated.

Exploitability

1. A malformed PSBT with an oversized length field can cause out-of-memory crashes or buffer overflows in the parser, leading to denial of service or remote code execution.
2. Duplicate keys in a PSBT map can cause inconsistent state if the parser processes them differently in different code paths (e.g., first-key-wins vs last-key-wins).
3. A PSBT with `nLockTime` set far in the future can lock funds indefinitely if the signer does not validate the timelock before signing.
4. Missing or incorrect `nSequence` can disable intended timelock enforcement (e.g., `nSequence = 0xFFFFFFFF` disables `nLockTime`).

Check

1. Implement strict PSBT parsing with bounded allocations, length validation, and duplicate key rejection.
2. Validate `nLockTime` against the protocol's expected range and ensure `nSequence` values are consistent with timelock requirements.
3. For BIP-370 PSBTv2, validate all required global fields and enforce version-specific constraints.
4. Add fuzzing tests with malformed PSBTs: oversized fields, truncated data, duplicate keys, invalid magic bytes, and extreme timelock values.
