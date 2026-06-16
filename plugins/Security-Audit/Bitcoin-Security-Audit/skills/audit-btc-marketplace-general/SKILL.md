---
name: audit-btc-marketplace-general
description: Audits Ordinals/BRC-20/Runes marketplace implementations for listing PSBT manipulation, inscription UTXO mismanagement, indexer trust failures, front-running and snipping attacks, fee manipulation, and platform trust boundary violations. Produces a findings.md report with ranked vulnerabilities.
when_to_use: |
  Use when user mentions "Ordinals marketplace", "BRC-20 trading", "Runes marketplace", "inscription trading", "Bitcoin NFT marketplace", "ordinal listing", "inscription snipping", "Bitcoin marketplace audit", "bitcoinjs-lib marketplace", "inscription UTXO", "cardinal ordinal separation", "Runestone", "@magiceden", "ord indexer" or asks about Ordinals/BRC-20/Runes trading security, PSBT-based listing flows, or inscription UTXO management.
  Do NOT use for EVM NFT marketplaces (OpenSea/Seaport) or non-inscription token trading.
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

# Bitcoin Marketplace Vulnerability Scanner

## 1. Introduction

Ordinals, BRC-20, and Runes have created a marketplace ecosystem built directly on Bitcoin's UTXO model. Unlike EVM-based NFT marketplaces that rely on smart contract escrow and `transferFrom` approvals, Bitcoin marketplaces use PSBTs as the order book primitive — sellers sign partial transactions that buyers complete. This architecture introduces unique attack surfaces: sighash flag misuse can grant buyers or platforms excessive modification rights over seller funds, inscription-bearing UTXOs can be accidentally destroyed through cardinal/ordinal confusion, and indexer trust assumptions create opportunities for double-spend-like attacks on BRC-20 balances.

Real-world incidents include BRC-20 snipping attacks documented in 2024 research where front-runners exploited `SIGHASH_SINGLE|ANYONECANPAY` listing PSBTs, inscription loss through accidental spending of inscription-bearing UTXOs as fee inputs, and BRC-20 balance inconsistencies across indexers enabling double-spend exploits. The marketplace attack surface spans PSBT construction and completion, ordinal theory indexing, BRC-20/Runes protocol consensus, mempool front-running, fee manipulation, and platform trust boundaries.

This skill covers Ordinals (inscription creation, transfer, and sat tracking), BRC-20 (deploy/mint/transfer inscription protocol), Runes (OP_RETURN-based fungible token protocol), and the PSBT-based listing/buying flows that connect them. It targets auditors reviewing marketplace backends, trading platforms, wallet integrations, and any system that constructs, validates, or executes inscription-related trades. All pseudocode uses Bitcoin transaction structure and Script semantics. For PSBT-specific construction and signing vulnerabilities, cross-reference the `audit-psbt-security` skill.

---

## 2. Purpose

This skill audits Ordinals/BRC-20/Runes marketplace implementations to detect listing PSBT manipulation, inscription UTXO mismanagement, indexer trust failures, front-running and snipping attacks, fee manipulation, and platform trust boundary violations in Bitcoin-native trading flows.

---

## 3. When to Use This Skill

**Prompt trigger**

```
Does the code implement a Bitcoin inscription marketplace (list/buy/sell)? ──yes──> Use this skill
│
no
│
v
Does it handle Ordinals inscription transfers or BRC-20 balance operations? ──yes──> Use this skill
│
no
│
v
Does it construct or complete PSBTs for inscription/token trading? ──yes──> Use this skill
│
no
│
v
Does it rely on an indexer (ord, OPI, Hiro) for inscription or balance state? ──yes──> Use this skill
│
no
│
v
Does it manage cardinal/ordinal UTXO separation or Runes etching/transfer? ──yes──> Use this skill
│
no
│
v
Skip this skill
```

**Concrete triggers**

- PSBT listing construction with `SIGHASH_SINGLE|ANYONECANPAY` for marketplace orders
- Inscription UTXO management (`inscription_utxo`, `cardinal_utxo`, ordinal/cardinal separation logic)
- BRC-20 operations (`brc-20 deploy`, `brc-20 mint`, `brc-20 transfer`, `inscribe`, `transfer inscription`)
- Runes operations (`Runestone`, `Edict`, `Etching`, `OP_RETURN`, rune ID parsing)
- Indexer queries (`ord`, `OPI`, `Hiro API`, `getInscription`, `getBRC20Balance`, `getRuneBalance`)
- Marketplace listing/buying flows (order book, listing PSBT, buyer completion, escrow)
- Inscription content parsing (`content-type`, `content-length`, envelope parsing, `OP_FALSE OP_IF`)
- Fee calculation for inscription trades, dust limit handling, padding UTXOs
- Snipping/front-running mitigation (time-bounded listings, atomic swaps, mempool monitoring)
- TypeScript SDK: `import * as bitcoin from "bitcoinjs-lib"`, `Psbt`, `bitcoin.payments.p2tr`
- TypeScript SDK: `fetchUtxos`, `fetchInscriptionUtxos`, cardinal/ordinal UTXO filtering
- TypeScript SDK: `@magiceden/ord-sdk`, `ord` API client, Hiro Ordinals API
- TypeScript SDK: `Runestone`, `Edict`, `OP_RETURN` builder, LEB128 encoding

## Additional resources

- For real-world TypeScript vulnerable patterns in marketplace backends, see [typescript-vulnerable-patterns.md](references/typescript-vulnerable-patterns.md)

---

## Goal

Produce a `findings.md` file containing all identified vulnerabilities in the target Bitcoin marketplace implementation, each with a title, code location, description, attack scenario, and fix recommendation. Every checkpoint in the checklist below must be evaluated. The audit is complete when all checkpoints have been checked and all findings are reported.

## Workflow

### Step 1: Establish scope
Identify the target files and modules that handle inscription trading, PSBT listing flows, indexer queries, or UTXO management. Confirm the project is a Bitcoin inscription marketplace and matches this skill's domain.

**Artifacts**: list of target files, confirmed project type
**Success criteria**: The target file set is known and confirmed to involve Bitcoin inscription marketplace logic.

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
- For PSBT-specific construction and signing vulnerabilities, note the cross-reference to `audit-psbt-security` but do not execute it.

---

## 4. Checklist

### Title: 0x0000-listing-psbt-sighash-must-not-grant-excessive-modification-rights

Description
Marketplace listings typically use `SIGHASH_SINGLE|ANYONECANPAY` so the seller commits to their input (the inscription UTXO) and one output (the payment to themselves), while the buyer can add funding inputs and additional outputs. Using a weaker sighash flag — such as `SIGHASH_NONE|ANYONECANPAY` or `SIGHASH_NONE` — grants the buyer or any intermediary the ability to redirect the seller's inscription with no payment obligation.

Identify

1. Locate the listing PSBT construction function — find where the seller's inscription UTXO is added as an input and the sighash flag is selected for signing.
2. Search for sighash flag constants or parameters in the listing flow: `SIGHASH_SINGLE`, `SIGHASH_ANYONECANPAY`, and any configurable or user-supplied sighash selection.
3. Check whether the sighash flag is hardcoded at the platform level or can be influenced by the seller, buyer, or API parameters.

Analyze

1. Verify the listing uses exactly `SIGHASH_SINGLE|ANYONECANPAY` (`0x83`) — this commits the seller to their specific input and the output at the same index (their payment output), while allowing the buyer to add inputs and additional outputs.
2. Check that the seller's payment output is placed at the same index as the seller's input to satisfy `SIGHASH_SINGLE` index matching — if the indices are misaligned, the seller's signature may not commit to their payment (or worse, trigger the `uint256(1)` bug on legacy/SegWit v0 inputs).
3. Verify that no code path downgrades the sighash to `SIGHASH_NONE` or `SIGHASH_NONE|ANYONECANPAY` based on transaction type, platform configuration, or error fallback.

Exploitability

1. If the listing uses `SIGHASH_NONE|ANYONECANPAY`, the buyer can strip all outputs and redirect the inscription UTXO to themselves without paying the seller — the seller's signature commits to no outputs at all.
2. If `SIGHASH_SINGLE` is used but the output index is mismatched, the seller's signature commits to `uint256(1)` (the SIGHASH_SINGLE bug), making the input anyone-can-spend — any observer can steal the inscription.
3. A platform that allows configurable sighash flags per listing type can be exploited if an attacker creates a listing with `SIGHASH_NONE` through the API.

Check

1. Hardcode listing sighash to `SIGHASH_SINGLE|ANYONECANPAY` and reject any listing PSBT signed with a different flag.
2. Enforce strict index alignment between the seller's input and their payment output before signing.
3. Add tests that attempt to complete a listing PSBT after substituting `SIGHASH_NONE|ANYONECANPAY` and verify the system rejects it.

---

### Title: 0x0001-seller-signed-psbt-must-not-be-replayable-across-listings

Description
A seller's signed listing PSBT remains valid as long as the UTXO it spends is unspent. If a seller creates a listing, cancels it (without spending the UTXO), and creates a new listing at a different price, the old signed PSBT is still valid and can be used by anyone who obtained it. This is the listing replay problem — stale listings at lower prices can be executed by buyers who cached the old PSBT.

Identify

1. Find the listing cancellation flow — determine whether cancellation spends the inscription UTXO (on-chain cancel) or merely removes the listing from the marketplace database (off-chain cancel).
2. Locate any listing storage or caching that could preserve stale signed PSBTs (marketplace API responses, CDN caches, buyer-side local storage, third-party aggregators).
3. Search for listing versioning or nonce mechanisms that invalidate previous listings for the same UTXO.

Analyze

1. Verify that listing cancellation invalidates the seller's signed PSBT on-chain — the only reliable way is to spend the inscription UTXO to a new address controlled by the seller (a "cancel transaction").
2. Check whether the platform implements off-chain cancellation (database deletion) as the sole cancellation mechanism — this leaves the signed PSBT valid and replayable by anyone who has a copy.
3. Verify that price updates also invalidate the previous listing PSBT — updating the price in the database without spending the UTXO leaves the old lower-price PSBT valid.

Exploitability

1. A buyer who cached a listing PSBT at 0.5 BTC can execute it even after the seller "cancelled" and relisted at 1.0 BTC, if the cancellation was off-chain only — the buyer completes the old PSBT and broadcasts it, buying the inscription at the old price.
2. Third-party aggregators or indexers that cache listing PSBTs can serve stale listings even after the originating marketplace has removed them.
3. An attacker can systematically collect listing PSBTs from marketplace APIs and execute them later when market conditions change, buying underpriced inscriptions.

Check

1. Implement on-chain cancellation by spending the inscription UTXO to a seller-controlled address whenever a listing is cancelled or price is updated.
2. If on-chain cancellation is too expensive, implement a time-bounded listing with `nLockTime` or `nSequence` so the PSBT becomes invalid after a specified block height or time.
3. Add tests that attempt to complete a cancelled or re-priced listing using the original PSBT and verify the transaction fails (UTXO already spent).

---

### Title: 0x0002-buyer-completion-must-not-allow-output-substitution-or-fee-manipulation

Description
When a buyer completes a seller's listing PSBT, they add funding inputs and additional outputs (inscription delivery to buyer, change). The buyer controls the fee rate and all non-committed outputs. A malicious buyer or a compromised platform completing on behalf of the buyer can manipulate fees to extract value, add outputs that redirect inscription fragments, or construct the completion in a way that destroys the inscription through dust limit violations.

Identify

1. Find the buyer completion flow — locate where the buyer adds their funding input(s), the inscription delivery output, and the change output(s) to the seller's signed PSBT.
2. Locate fee calculation in the completion flow — determine whether the fee is computed from the transaction virtual size and a target fee rate, and whether any bounds are enforced.
3. Search for output validation after buyer completion — does the platform verify that the completed PSBT matches expected parameters before broadcast?

Analyze

1. Verify that the buyer cannot substitute the seller's committed output — with `SIGHASH_SINGLE|ANYONECANPAY`, the seller's payment output (at the matched index) is committed by the seller's signature and cannot be modified by the buyer.
2. Check that the buyer's added outputs include the inscription delivery output with exactly the correct value (typically 546 satoshis dust limit) to the buyer's address, and that no extra outputs split or redirect the inscription.
3. Verify fee bounds: the fee should be `sum(inputs) - sum(outputs)` and must not exceed a maximum fee rate (sat/vB) or absolute maximum — an excessive fee can extract value from the buyer's inputs to colluding miners.

Exploitability

1. A compromised platform completing trades on behalf of buyers can inflate the fee to extract value from the buyer's funding inputs — the excess fee goes to miners (potentially colluding with the platform).
2. If the completion flow does not validate the inscription delivery output, the buyer could omit it, effectively burning the inscription (it would go to the miner as fee if the UTXO amount is above dust).
3. A buyer can construct the completion to send the inscription output to a different address than their own, enabling a "purchase for someone else" attack if the platform uses the buyer's completion to confirm purchase authorization.

Check

1. Enforce fee rate bounds on the completed transaction before broadcast — reject completion if the fee exceeds a configurable maximum sat/vB rate or absolute ceiling.
2. Validate that the completed PSBT contains exactly the expected outputs: seller payment (committed by seller's signature), inscription delivery to the authorized buyer address, and buyer change.
3. Add tests that submit completions with inflated fees, missing inscription outputs, and substituted delivery addresses, confirming the platform rejects each.

---

### Title: 0x0003-ordinal-utxo-must-be-separated-from-cardinal-utxo-to-prevent-accidental-spend

Description
In ordinal theory, every satoshi has a unique ordinal number based on its mining order. Inscriptions are attached to specific satoshis. A UTXO containing an inscribed satoshi is an "ordinal UTXO" — spending it transfers the inscription according to ordinal theory's sat-tracking rules. If a wallet or marketplace treats inscription-bearing UTXOs as regular ("cardinal") UTXOs for fee payment, change, or consolidation, the inscription can be accidentally transferred, destroyed, or sent to an unintended recipient.

Identify

1. Find the UTXO selection logic — locate where the wallet or marketplace selects UTXOs for spending, fee payment, or change and determine whether it distinguishes between ordinal (inscription-bearing) and cardinal (regular) UTXOs.
2. Search for inscription-awareness in the UTXO database — does the system tag or categorize UTXOs based on whether they contain inscriptions?
3. Locate consolidation, sweep, or batch-spending operations that might inadvertently include inscription UTXOs.

Analyze

1. Verify that the UTXO selector explicitly excludes inscription-bearing UTXOs from cardinal operations (fee payment, change inputs, consolidation, dust cleanup).
2. Check that the inscription detection mechanism is reliable — it should query an indexer or maintain a local database of inscription-bearing UTXOs, not rely solely on UTXO amount (not all dust UTXOs contain inscriptions, and not all inscriptions are on dust UTXOs).
3. Verify that newly received UTXOs are scanned for inscriptions before being added to the spendable cardinal pool — a race between receiving a UTXO and indexing its inscription status could cause premature spending.

Exploitability

1. A wallet that uses all available UTXOs for fee estimation and coin selection can accidentally include an inscription UTXO as a fee input in an unrelated transaction — the inscription is transferred to the recipient or burned as fee.
2. An attacker can send an inscription to a victim's address embedded in a UTXO that the victim's wallet treats as cardinal — when the victim consolidates UTXOs or makes a payment, the inscription is inadvertently spent.
3. During high-fee environments, UTXO consolidation routines that sweep small UTXOs (including inscription-bearing dust) destroy inscriptions by merging them into a larger UTXO without preserving sat ordering.

Check

1. Implement explicit cardinal/ordinal UTXO separation: maintain separate UTXO pools and never use ordinal UTXOs for cardinal operations.
2. Scan all incoming UTXOs against the inscription indexer before adding them to the cardinal pool — quarantine unknown UTXOs until indexer confirmation.
3. Add tests that inject inscription-bearing UTXOs into the cardinal pool and verify the UTXO selector excludes them from fee payment and consolidation.

---

### Title: 0x0004-inscription-bearing-utxo-must-not-be-used-as-fee-input-or-padding

Description
Marketplace platforms often add "padding" UTXOs to a transaction to meet the dust limit on outputs or to provide fee funding. If padding UTXO selection does not exclude inscription-bearing UTXOs, inscriptions owned by the platform or the user can be accidentally destroyed. Similarly, using an inscription UTXO as a fee input in a batch transaction transfers the inscription to an unintended party.

Identify

1. Find the padding UTXO selection logic — locate where the platform selects UTXOs to add as additional inputs for fee funding or dust limit compliance.
2. Search for fee input selection in batch operations — determine whether the platform uses a general UTXO pool or a filtered pool that excludes inscriptions.
3. Locate any UTXO consolidation or cleanup routines that might sweep inscription-bearing UTXOs.

Analyze

1. Verify that padding and fee UTXOs are selected exclusively from the cardinal pool — no inscription-bearing UTXO should ever appear in a padding or fee role.
2. Check that the padding logic considers the sat value of the UTXO relative to the inscription position — ordinal theory tracks which specific satoshi within a UTXO bears the inscription, so partial spending or UTXO splitting can move the inscription to an unintended output.
3. Verify that the platform does not hold user inscriptions in a shared UTXO pool with cardinal funds — commingling risks accidental spending.

Exploitability

1. A platform that selects padding UTXOs from an unfiltered pool can accidentally spend a high-value inscription (e.g., a rare sat or a high-value BRC-20 transfer inscription) as fee padding in an unrelated trade, destroying the inscription's intended transfer.
2. If the platform uses a UTXO containing multiple inscriptions (parent inscriptions with children), splitting that UTXO for padding can separate parent and child inscriptions, breaking collections.
3. An attacker can intentionally send inscriptions to the platform's hot wallet address, causing the platform to accidentally spend them as padding — a griefing attack that can destroy third-party inscriptions.

Check

1. Filter all UTXO selection for padding and fee inputs through an inscription-exclusion check — query the indexer before selecting any UTXO for non-inscription purposes.
2. Implement a quarantine period for newly received UTXOs before they become eligible for padding or fee use — allow the indexer to catch up.
3. Add tests that place inscription-bearing UTXOs in the padding pool and verify the selection logic excludes them.

---

### Title: 0x0005-indexer-state-must-be-verified-independently-before-trade-execution

Description
Bitcoin inscription marketplaces depend on indexers (ord, OPI, Hiro, custom indexers) to determine inscription ownership, BRC-20 balances, and Runes holdings. These indexers parse Bitcoin transactions and maintain off-chain state. If the marketplace trusts a single indexer without independent verification, indexer bugs, lag, or manipulation can cause trades to execute against incorrect state — selling inscriptions that have already been transferred, or accepting BRC-20 transfers that the indexer has not yet processed.

Identify

1. Find all indexer queries in the trade execution flow — locate API calls to `ord`, `OPI`, `Hiro`, or custom indexer endpoints that determine inscription ownership, BRC-20 balances, or Runes holdings.
2. Determine whether the marketplace uses a single indexer or cross-references multiple indexers.
3. Locate the timing relationship between indexer query and trade execution — is there a gap where the indexer state can change between query and execution?

Analyze

1. Verify that the marketplace cross-references at least two independent indexers for ownership and balance queries before executing trades — a single indexer can have bugs, lag, or be compromised.
2. Check the block height or timestamp of the indexer state relative to the current chain tip — stale indexer state (even a few blocks behind) can show inscriptions that have already been transferred in recent blocks.
3. Verify that the marketplace re-validates indexer state at trade execution time, not just at listing time — an inscription could be transferred between listing and purchase.

Exploitability

1. An attacker transfers an inscription to themselves (spending the inscription UTXO on-chain), then immediately sells the inscription on a marketplace whose indexer has not yet processed the transfer — the buyer pays for an inscription the seller no longer owns.
2. An indexer bug that miscounts BRC-20 transfer inscription validity can show inflated balances — a user can sell BRC-20 tokens they do not actually hold according to consensus rules.
3. During Bitcoin chain reorgs, indexer state can temporarily revert — an attacker can exploit the reorg window to re-sell an inscription that was already transferred in the now-orphaned block.

Check

1. Cross-reference at least two independent indexers before executing any trade — halt the trade if the indexers disagree on ownership or balance.
2. Enforce minimum confirmation depth before accepting inscription transfers as final — do not allow trading of inscriptions in unconfirmed or recently confirmed transactions (1-2 blocks minimum).
3. Add tests that simulate indexer lag (stale state) and indexer disagreement, confirming the marketplace halts trade execution.

---

### Title: 0x0006-brc20-balance-transfers-must-validate-inscription-validity-against-consensus-rules

Description
BRC-20 is an experimental token standard where balances are tracked via inscriptions containing JSON payloads (`{"p":"brc-20","op":"transfer","tick":"ordi","amt":"100"}`). The validity of a BRC-20 transfer depends on complex rules: the inscription must be a valid `transfer` type, the amount must not exceed the sender's available balance (which itself depends on all prior `deploy`, `mint`, and `transfer` inscriptions for that tick), and the transfer inscription must be sent (spent) to the recipient in a subsequent transaction. Marketplaces that do not fully validate these rules risk executing trades on invalid or already-consumed transfer inscriptions.

Identify

1. Find BRC-20 balance computation logic — locate where the marketplace calculates a user's available BRC-20 balance from inscription history.
2. Search for BRC-20 transfer inscription validation — does the marketplace verify the inscription JSON payload, check the amount against the sender's balance, and confirm the transfer inscription has not already been consumed?
3. Locate the "send" step — BRC-20 requires two steps: first inscribe a `transfer` inscription, then send (spend) the UTXO containing the transfer inscription to the recipient.

Analyze

1. Verify that the marketplace validates the full BRC-20 state machine: `deploy` → `mint` (up to `max` supply, respecting `lim` per mint) → `transfer` (up to sender's available balance) → `send` (spending the transfer inscription UTXO).
2. Check that the marketplace rejects transfer inscriptions that exceed the sender's available balance — the balance must account for all pending (inscribed but not yet sent) transfer inscriptions, not just completed transfers.
3. Verify that the marketplace detects "double-send" attempts — a transfer inscription can only be sent once; if the UTXO containing it has already been spent, the transfer inscription is consumed regardless of whether the spend went to the intended recipient.

Exploitability

1. A seller inscribes a `transfer` inscription for 100 ORDI, lists it on marketplace A, and simultaneously lists a separate `transfer` inscription for the same 100 ORDI on marketplace B. If both marketplaces validate against the same available balance without accounting for the other pending transfer, both sales can succeed — a BRC-20 double-spend.
2. An attacker exploits indexer differences in BRC-20 rule interpretation (e.g., some indexers accept case-insensitive ticks, others do not) to show a valid balance on one indexer while the inscription is invalid on the consensus indexer.
3. A transfer inscription inscribed in a transaction that also contains a non-standard or invalid envelope can be rejected by some indexers but accepted by others — the marketplace that accepts it sells a token that does not exist according to consensus.

Check

1. Validate BRC-20 transfer inscriptions against the canonical BRC-20 indexer consensus rules — do not implement custom rule interpretation.
2. Account for pending (inscribed but unsent) transfer inscriptions when computing available balance — deduct pending transfer amounts from the available balance.
3. Add tests with double-spend transfer inscriptions, over-balance transfers, and invalid inscription payloads, confirming the marketplace rejects each.

---

### Title: 0x0007-runes-etching-and-transfer-must-validate-runestone-op-return-structure

Description
Runes is a fungible token protocol on Bitcoin that uses an `OP_RETURN` output containing a "Runestone" data structure to encode token operations (etching, minting, and transfers via edicts). The Runestone uses a compact integer encoding and strict field ordering. Malformed Runestones are treated as "cenotaphs" — invalid Runestones that burn all Runes input to the transaction. Marketplaces that construct or parse Runestones incorrectly risk burning user tokens or executing trades on invalid Runes state.

Identify

1. Find Runestone construction and parsing logic — locate where the marketplace creates `OP_RETURN` outputs containing Runestone data or parses them from incoming transactions.
2. Search for Runes transfer (edict) construction — does the marketplace correctly encode `Edict { id, amount, output }` entries?
3. Locate Runes balance queries and verify which indexer or parser the marketplace uses for Runes state.

Analyze

1. Verify that Runestone construction follows the canonical encoding: correct `OP_RETURN` prefix, valid tag-value pairs in ascending order, properly encoded varints, and valid edict structure with ascending rune ID order within edicts.
2. Check that the marketplace detects cenotaph conditions — any malformed Runestone burns all Runes in the transaction's inputs. The marketplace must validate Runestone well-formedness before constructing or broadcasting transactions.
3. Verify that Runes transfers correctly specify the output index for each edict — an incorrect output index sends Runes to the wrong party or burns them if the output index is beyond the transaction's output count.

Exploitability

1. A malformed Runestone that the marketplace constructs (e.g., out-of-order tags, invalid varint encoding) is treated as a cenotaph by consensus — all Runes in the transaction's inputs are burned, destroying user tokens.
2. An attacker submits a trade where the Runestone's edict specifies an output index pointing to the attacker's output instead of the buyer's — the Runes are redirected to the attacker while the buyer pays the seller.
3. If the marketplace's Runestone parser differs from the consensus parser (e.g., handling of duplicate tags, unknown flags), the marketplace may show Runes balances that do not match on-chain state.

Check

1. Use the canonical Runes parser (ord reference implementation) for Runestone construction and validation — do not implement custom parsing that may diverge from consensus.
2. Validate every Runestone for cenotaph conditions before broadcast — check tag ordering, varint encoding, edict ordering, and output index bounds.
3. Add tests that construct malformed Runestones (out-of-order tags, invalid varints, out-of-bounds output indices) and verify the marketplace detects them as cenotaphs.

---

### Title: 0x0008-inscription-content-type-and-size-must-be-validated-to-prevent-parsing-attacks

Description
Inscriptions carry arbitrary content (images, HTML, JavaScript, JSON, text) identified by a content-type field in the inscription envelope. Marketplaces that render inscription content (displaying images, executing HTML/JS) without validating the content type and size are vulnerable to cross-site scripting (XSS), content spoofing, resource exhaustion, and inscription confusion attacks where the displayed content does not match what is actually inscribed.

Identify

1. Find inscription content rendering logic — locate where the marketplace displays inscription content to users (image rendering, HTML/JS execution, text display).
2. Search for content-type validation — does the marketplace verify the inscription's claimed content-type matches the actual content, and does it restrict which content types are rendered?
3. Locate content size limits and resource allocation for inscription rendering.

Analyze

1. Verify that the marketplace validates the inscription content-type against a strict allowlist (e.g., `image/png`, `image/jpeg`, `image/webp`, `text/plain`) and does not render executable content types (`text/html`, `application/javascript`) without sandboxing.
2. Check that content-type validation matches the actual content — an inscription claiming `image/png` content-type but containing HTML/JavaScript can bypass content-type restrictions if the renderer trusts the claimed type.
3. Verify that inscription content size is bounded — extremely large inscriptions (multi-MB images or recursive inscriptions) can cause resource exhaustion in rendering.

Exploitability

1. An inscription with `text/html` content-type containing JavaScript is rendered in the marketplace UI — the JavaScript executes in the user's browser context, enabling XSS (stealing session tokens, initiating trades, redirecting users to phishing sites).
2. Content-type confusion: an inscription claims `image/png` but contains SVG with embedded JavaScript — the marketplace renders it as an image but the browser interprets the SVG and executes the script.
3. A recursive inscription (an inscription that references other inscriptions) can create infinite rendering loops, causing denial-of-service for users viewing the marketplace page.

Check

1. Implement strict content-type allowlisting — only render known-safe types (raster images, plain text) and sandbox or reject executable content types.
2. Validate content bytes against the claimed content-type using magic byte detection (PNG header `89504E47`, JPEG header `FFD8FF`, etc.) — do not trust the inscription's declared content-type alone.
3. Add tests that submit inscriptions with XSS payloads in various content types and verify the marketplace sanitizes or rejects them.

---

### Title: 0x0009-snipping-attack-must-be-mitigated-via-atomic-swap-or-time-bounded-listing

Description
A snipping attack occurs when an attacker observes a seller's listing PSBT (signed with `SIGHASH_SINGLE|ANYONECANPAY`) and constructs a competing buy transaction with a higher fee, front-running the legitimate buyer. Because the seller's signature is valid in any transaction that preserves the committed input and matched output, anyone with access to the signed PSBT can construct a valid buy transaction. This is the primary front-running vector in PSBT-based marketplaces.

Identify

1. Find where listing PSBTs are distributed — are they publicly available via API, stored in a database queryable by any user, or transmitted directly between seller and buyer?
2. Locate any anti-front-running mechanisms: time-bounded listings, commit-reveal schemes, atomic swap protocols, or private PSBT channels.
3. Search for RBF (Replace-By-Fee) handling in the buy transaction construction — can a snipping attacker use RBF to replace the legitimate buyer's pending transaction?

Analyze

1. Verify whether listing PSBTs are publicly accessible — if anyone can query the marketplace API for signed listing PSBTs, snipping is trivially achievable.
2. Check whether the marketplace implements time-bounded listings using `nLockTime` or `nSequence` to limit the validity window of the listing PSBT.
3. Verify whether the buy flow uses a commit-reveal or atomic swap pattern — a two-phase buy where the buyer commits to the purchase (with a deposit or hash lock) before the listing PSBT is revealed prevents snipping.

Exploitability

1. An attacker runs a bot that queries the marketplace API for new listings, extracts the signed PSBT, constructs a competing buy transaction with a higher fee rate, and broadcasts it — the attacker's transaction confirms first, and the legitimate buyer's transaction is invalidated (double-spend of the seller's input).
2. Even without API access, an attacker monitoring the mempool can see a buyer's pending completion transaction, extract the seller's signature from it, and construct a replacement transaction with a higher fee (if RBF is signaled).
3. In high-demand drops (popular collections, BRC-20 token launches), snipping bots systematically front-run human buyers, extracting value from the market.

Check

1. Implement a commit-reveal purchase flow: the buyer commits a deposit or hash preimage before the listing PSBT is revealed, preventing unauthorized third parties from constructing competing transactions.
2. Use time-bounded listings with short validity windows (`nLockTime` set to current block height + N blocks) to limit the exposure window for snipping.
3. Add tests that simulate a snipping attack (two competing buy transactions using the same listing PSBT) and verify the marketplace's mitigation prevents the sniper from succeeding.

---

### Title: 0x000a-mempool-observation-must-not-enable-sandwich-attacks-on-marketplace-trades

Description
Bitcoin's public mempool allows anyone to observe pending (unconfirmed) transactions. In marketplace contexts, mempool observation reveals trading intent — an attacker can see a pending buy transaction and construct front-running or back-running transactions to profit from the information. While Bitcoin does not have the same DEX-style sandwich attack surface as Ethereum (no AMMs with deterministic pricing), mempool observation still enables snipping (front-running buy transactions), fee bidding wars on competitive purchases, and information leakage about market demand.

Identify

1. Find where marketplace transactions enter the mempool — locate broadcast logic and determine whether transactions are broadcast immediately after completion or batched.
2. Search for any private mempool or direct-to-miner submission mechanisms (e.g., Blockstream satellite, direct miner APIs, transaction accelerators).
3. Locate any mempool monitoring in the marketplace itself — does the platform watch the mempool for competing transactions or trade confirmations?

Analyze

1. Verify whether the marketplace's buy flow exposes transaction details to the public mempool before confirmation — specifically, whether the seller's signed PSBT data is visible in the pending transaction.
2. Check whether the platform uses any transaction privacy techniques: broadcasting via private relay, using full-RBF protections, or batching transactions to reduce individual visibility.
3. Verify that the marketplace monitors for mempool-based attacks and can respond to competing transactions (e.g., fee bumping the legitimate buyer's transaction via CPFP).

Exploitability

1. An attacker observing the mempool sees a pending buy transaction for a high-value inscription. They extract the seller's listing signature from the pending transaction and construct a replacement transaction with a higher fee — the attacker's transaction confirms first, and the legitimate buyer loses the inscription.
2. Mempool observation reveals demand for specific inscriptions or BRC-20 tokens, enabling the attacker to front-run by listing and buying related assets before the market price adjusts.
3. In a fee bidding war, two competing buyers repeatedly bump their transaction fees via RBF, escalating costs far beyond the inscription's value — the winner overpays, and the excess goes to miners.

Check

1. Minimize mempool exposure by using private transaction relay or direct-to-miner submission for high-value trades.
2. Disable RBF on buy transactions by setting `nSequence = 0xFFFFFFFF` on all inputs, preventing fee-based replacement attacks (note: full-RBF nodes may still accept replacements).
3. Add monitoring for competing transactions in the mempool and implement automatic CPFP fee bumping for the legitimate buyer's transaction when a competing transaction is detected.

---

### Title: 0x000b-marketplace-fee-and-royalty-outputs-must-be-immutable-and-auditable

Description
Marketplace platforms charge fees (platform commission) and may enforce creator royalties on inscription trades. These are implemented as additional outputs in the buy transaction. If fee and royalty outputs are not committed by the seller's signature and are constructed solely by the buyer or platform at completion time, they can be manipulated — fees can be reduced to zero, royalties can be skipped, or fee outputs can be redirected to attacker-controlled addresses.

Identify

1. Find where marketplace fee and royalty outputs are added to the buy transaction — are they part of the seller-signed PSBT or added during buyer completion?
2. Locate fee and royalty calculation logic — determine whether amounts are computed on-chain (committed in the PSBT) or off-chain (calculated by the platform at completion time).
3. Search for fee/royalty validation after buyer completion — does the platform verify that the correct fee and royalty outputs are present before broadcast?

Analyze

1. Verify that the seller's `SIGHASH_SINGLE|ANYONECANPAY` signature commits to the seller's payment output — but note that this does NOT commit to fee or royalty outputs, which are at different indices.
2. Check whether the platform validates fee and royalty outputs in the completed transaction before broadcast — without server-side validation, the buyer can modify or remove these outputs.
3. Verify that fee and royalty addresses are controlled by the platform and creator respectively, and cannot be substituted by the buyer or a third party.

Exploitability

1. A buyer constructing their own completion transaction can omit the marketplace fee output entirely, paying only the seller and saving the platform commission — the seller's signature remains valid because it only commits to the seller's own output.
2. A buyer can redirect the royalty output to their own address, appearing to pay royalties while actually receiving the royalty payment back.
3. A compromised platform can inflate fee outputs, extracting excessive fees from trades — the seller cannot detect this because their signature does not commit to non-matched outputs.

Check

1. Implement server-side validation of completed transactions before broadcast: verify that marketplace fee and royalty outputs are present with correct amounts and addresses.
2. Consider a co-signing model where the platform adds its own signature to the completed transaction, committing to the fee and royalty outputs.
3. Add tests that submit completed transactions with missing, reduced, or redirected fee and royalty outputs, confirming the platform rejects them.

---

### Title: 0x000c-platform-must-not-inject-additional-inputs-from-seller-wallet

Description
When a seller lists an inscription, they sign a PSBT spending their inscription UTXO. A malicious or compromised platform can modify the PSBT before presenting it to the seller for signing — adding additional inputs from the seller's wallet. If the seller signs without verifying the complete input set, the platform obtains valid signatures over the seller's additional UTXOs, which can be spent in a separate transaction.

Identify

1. Find the PSBT construction flow for listings — determine who constructs the initial PSBT (seller's wallet, platform backend, or a combination).
2. Locate the seller's signing step — does the seller verify all inputs in the PSBT before signing, or does the signing UI only display the inscription UTXO?
3. Search for any input-modification between PSBT construction and seller signing (platform backend, proxy server, API middleware).

Analyze

1. Verify that the seller's wallet or signing interface displays ALL inputs in the PSBT, not just the expected inscription UTXO — the seller must confirm the complete input set before producing a signature.
2. Check that the PSBT is constructed client-side (in the seller's wallet) and the platform only receives the signed PSBT — if the platform constructs the PSBT server-side, it can inject inputs.
3. Verify that the seller's sighash flag (`SIGHASH_SINGLE|ANYONECANPAY`) limits the damage of input injection — `ANYONECANPAY` means the seller's signature only commits to their own input, so injected inputs would need separate signatures. But if the seller is tricked into signing multiple inputs, the injected inputs are authorized.

Exploitability

1. A malicious platform constructs a PSBT with the seller's inscription UTXO plus a high-value cardinal UTXO from the seller's wallet. The seller's wallet only displays "Listing inscription X" without showing the additional input. The seller signs both inputs, and the platform broadcasts a transaction spending both UTXOs — the inscription goes to the buyer, and the cardinal UTXO's value goes to the platform.
2. Even with `SIGHASH_SINGLE|ANYONECANPAY`, if the platform presents a PSBT where the seller is asked to sign multiple inputs (claiming it is needed for "fee padding"), the seller produces valid signatures on each, authorizing the platform to spend those UTXOs.

Check

1. Construct listing PSBTs client-side in the seller's wallet — the platform should receive only the signed PSBT, never construct it for the seller.
2. Display ALL inputs and outputs to the seller before signing — wallet UIs must show the complete input set, total input value, and total output value.
3. Add tests that inject additional seller-owned inputs into listing PSBTs and verify the seller's wallet rejects signing or displays a clear warning.

---

### Title: 0x000d-escrow-and-custodial-flows-must-enforce-timelock-based-refund-paths

Description
Some marketplaces use escrow or custodial patterns where the seller transfers their inscription to a platform-controlled address before listing. This creates trust dependency on the platform — if the platform disappears, is compromised, or refuses to release the inscription, the seller loses their asset. Secure escrow must include a timelock-based refund path that allows the seller to recover their inscription after a deadline without platform cooperation.

Identify

1. Find the escrow or custodial flow — locate where inscriptions are transferred to platform-controlled addresses for listing.
2. Search for refund or recovery mechanisms — does the escrow include a time-locked refund path (e.g., a Taproot output with a platform key path and a seller timelock script path)?
3. Locate the escrow UTXO script — determine whether it uses a simple single-key output (platform controls everything) or a multi-path script with fallback conditions.

Analyze

1. Verify that escrow UTXOs use a multi-path script: (a) a cooperative path where the platform and buyer/seller can complete the trade, and (b) a timelock refund path where the seller can unilaterally recover the inscription after a deadline.
2. Check that the timelock duration is appropriate — too short and the platform cannot complete trades; too long and the seller's funds are locked excessively.
3. Verify that the refund path cannot be exploited by the seller to reclaim the inscription after the trade has been executed — the trade execution should spend the escrow UTXO, invalidating the refund path.

Exploitability

1. An escrow that uses a single-key output (platform's key only) gives the platform unilateral control over the inscription — the platform can refuse to release it, hold it hostage for additional fees, or steal it outright.
2. If the refund timelock is too short, the seller can reclaim the inscription after the buyer has already paid (via a separate channel), executing a "refund attack."
3. If the escrow script has a key-path spending option (Taproot internal key controlled by the platform), the platform can bypass all script-path conditions and spend the inscription at any time, regardless of timelock or multisig requirements.

Check

1. Implement escrow using Taproot outputs with: (a) key-path disabled (NUMS internal key), (b) script-path leaf 1: platform + seller cooperation (immediate trade execution), (c) script-path leaf 2: seller-only with `OP_CHECKLOCKTIMEVERIFY` timelock (refund after deadline).
2. Set the timelock to a reasonable duration (e.g., 144 blocks / ~1 day for active listings, longer for auction-style listings).
3. Add tests that attempt to spend the escrow via key path (should fail with NUMS key), via refund path before timelock (should fail), and via refund path after timelock (should succeed).

---

### Title: 0x000e-dust-limit-handling-must-not-destroy-inscriptions-or-create-unspendable-outputs

Description
Bitcoin's dust limit (546 satoshis for P2PKH/P2WPKH, 330 for P2TR) is the minimum output value that standard nodes will relay. Inscriptions are typically attached to dust-value UTXOs (546 or 330 satoshis). Marketplace transactions that create outputs below the dust limit will be rejected by standard mempool policies. Conversely, transactions that fail to account for dust limits may create inscription-bearing outputs with insufficient value, making them unspendable by standard transactions and effectively destroying the inscription.

Identify

1. Find output value calculation in marketplace transactions — locate where inscription delivery outputs, change outputs, and fee outputs are assigned their satoshi values.
2. Search for dust limit checks — does the marketplace validate that all outputs meet the dust limit before constructing or broadcasting the transaction?
3. Locate any inscription-bearing output construction and verify the output value meets the appropriate dust threshold for the output script type.

Analyze

1. Verify that inscription delivery outputs are created with at least the dust limit value for their script type (546 sats for P2WPKH, 330 sats for P2TR) — outputs below the dust limit will be rejected by standard mempools.
2. Check that change outputs from inscription trades also meet the dust limit — a trade that consumes most of the buyer's input value can leave change below the dust limit, which is either rejected (transaction fails) or the change is added to the fee (value lost).
3. Verify that the marketplace accounts for the dust limit when computing the minimum listing price — a listing at 500 sats on a P2WPKH output cannot create a valid buyer completion because the inscription delivery output would be below the 546-sat dust limit.

Exploitability

1. A marketplace that does not enforce dust limits on inscription delivery outputs creates transactions that standard nodes reject — the trade fails, and if the transaction reaches a non-standard miner, it may create an output that is unspendable by standard transactions, effectively locking the inscription.
2. A crafted listing at a very low price can force the buyer's change output below the dust limit, causing the buyer to lose the change amount as additional fee.
3. An attacker can manipulate the dust limit interaction by sending inscriptions on non-standard output types with higher dust thresholds, causing marketplace transactions to fail unexpectedly.

Check

1. Enforce dust limit validation on all outputs before constructing or broadcasting marketplace transactions — use the correct dust threshold for each output's script type.
2. Enforce a minimum listing price that ensures both the inscription delivery output and the buyer's change output can meet the dust limit.
3. Add tests that construct marketplace transactions with outputs at, below, and above the dust limit for various script types, confirming the system rejects sub-dust outputs.

---

### Title: 0x000f-marketplace-api-must-not-expose-partial-psbt-state-to-unauthorized-parties

Description
Marketplace APIs that expose signed listing PSBTs to unauthenticated or unauthorized parties enable snipping attacks, information leakage, and unauthorized trade execution. The signed PSBT contains the seller's valid signature — anyone who obtains it can construct a buy transaction. API security for PSBT-based marketplaces must balance discoverability (buyers need to find listings) with security (PSBTs should not be freely downloadable by bots).

Identify

1. Find the marketplace API endpoints that serve listing data — determine which endpoints return the signed PSBT blob and which return only metadata (price, inscription ID, seller address).
2. Search for authentication and authorization on PSBT retrieval endpoints — is the signed PSBT available to any API consumer, or only to authenticated buyers who have committed to a purchase?
3. Locate rate limiting, bot detection, and access control on listing APIs.

Analyze

1. Verify that the signed PSBT is not included in listing metadata endpoints — listing discovery should show price, inscription details, and preview without exposing the seller's signature.
2. Check that PSBT retrieval requires authentication and a purchase commitment (deposit, hash lock, or session binding) — the PSBT should only be released to a buyer who has demonstrated intent to complete the trade.
3. Verify that the API implements rate limiting and bot detection to prevent systematic harvesting of listing PSBTs.

Exploitability

1. An unauthenticated API that returns signed PSBTs enables automated snipping bots to harvest listings and front-run legitimate buyers at scale.
2. Exposed PSBTs can be cached and replayed after listing cancellation (if cancellation is off-chain only — see checkpoint 0x0001), enabling stale trade execution.
3. Bulk PSBT harvesting can be used for market analysis — an attacker can estimate marketplace volume, seller behavior, and pricing trends from the exposed PSBT data, gaining unfair trading advantage.

Check

1. Separate listing metadata endpoints (public, no PSBT) from PSBT retrieval endpoints (authenticated, requires purchase commitment).
2. Implement a commit-reveal flow where the buyer deposits a commitment before the PSBT is revealed, ensuring only committed buyers access the signature material.
3. Add tests that attempt unauthenticated PSBT retrieval, bulk PSBT harvesting, and replaying cached PSBTs after listing cancellation, confirming the API rejects each.
