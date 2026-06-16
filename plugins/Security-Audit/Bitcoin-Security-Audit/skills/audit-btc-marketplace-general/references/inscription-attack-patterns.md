# Inscription Attack Patterns

This document catalogs six vulnerable patterns in Ordinals/BRC-20/Runes marketplace implementations with pseudocode demonstrations. Each pattern corresponds to one or more checkpoints in the main SKILL.md checklist.

---

## 1. Snipping Attack on PSBT Listing

**Related checkpoint:** 0x0009

**Vulnerability:** A seller's listing PSBT signed with `SIGHASH_SINGLE|ANYONECANPAY` is publicly available. An attacker observes a legitimate buyer's pending completion transaction and constructs a competing transaction with a higher fee, front-running the buyer and stealing the inscription purchase.

```
# Seller lists inscription via PSBT
seller_psbt = create_psbt()
seller_psbt.add_input(utxo=inscription_utxo, value=546 sats)
seller_psbt.add_output(address=seller, value=0.1 BTC)  # payment at index 0
seller_sig = sign(seller_psbt, input_0, sighash=SIGHASH_SINGLE|ANYONECANPAY, key=seller)

# Marketplace publishes signed PSBT via public API
marketplace.store_listing(seller_psbt)

# === Legitimate buyer constructs completion ===
buyer_psbt = seller_psbt.clone()
buyer_psbt.add_input(utxo=buyer_funding, value=0.2 BTC)
buyer_psbt.add_output(address=buyer, value=546 sats)         # inscription delivery
buyer_psbt.add_output(address=platform, value=0.005 BTC)     # platform fee
buyer_psbt.add_output(address=buyer_change, value=0.0949 BTC)
buyer_sig = sign(buyer_psbt, input_1, key=buyer)
broadcast(buyer_psbt)  # enters mempool with fee rate 10 sat/vB

# === Snipping attacker monitors mempool ===
# Attacker sees buyer's pending tx, extracts seller's signature
snipe_psbt = create_psbt()
snipe_psbt.add_input(utxo=inscription_utxo, value=546 sats)
snipe_psbt.set_signature(input_0, seller_sig)  # reuse seller's valid signature
snipe_psbt.add_input(utxo=attacker_funding, value=0.3 BTC)
snipe_psbt.add_output(address=seller, value=0.1 BTC)         # must match seller's commitment
snipe_psbt.add_output(address=attacker, value=546 sats)       # inscription to attacker
snipe_psbt.add_output(address=attacker_change, value=0.1998 BTC)
snipe_sig = sign(snipe_psbt, input_1, key=attacker)
# Broadcast with higher fee rate to outbid buyer
broadcast(snipe_psbt)  # fee rate 50 sat/vB — miners prefer this

# Result: attacker gets inscription, seller gets paid, buyer's tx is invalidated
# Buyer's funding UTXO is returned (not spent), but they lose the inscription
```

**Why it works:** `SIGHASH_SINGLE|ANYONECANPAY` only commits the seller's signature to their own input and the output at the same index. Any party with access to the signed PSBT can construct a valid competing transaction. The highest-fee transaction wins in the mempool.

**Mitigation:** Commit-reveal purchase flow, time-bounded listings, or private PSBT channels that prevent unauthorized access to the seller's signature.

---

## 2. Inscription Theft via Cardinal/Ordinal UTXO Confusion

**Related checkpoints:** 0x0003, 0x0004

**Vulnerability:** A wallet or marketplace treats an inscription-bearing UTXO as a regular (cardinal) UTXO and includes it in a payment, fee funding, or consolidation transaction. The inscription is transferred to an unintended recipient or burned as fee.

```
# User's wallet UTXO pool (unfiltered)
utxo_pool = [
    { outpoint: "abc:0", value: 0.5 BTC,   has_inscription: false },  # cardinal
    { outpoint: "def:0", value: 546 sats,  has_inscription: true  },  # ordinal (rare sat #1234567)
    { outpoint: "ghi:0", value: 0.3 BTC,   has_inscription: false },  # cardinal
    { outpoint: "jkl:0", value: 10000 sats, has_inscription: true  },  # ordinal (BRC-20 transfer)
]

# === Vulnerable wallet: no cardinal/ordinal separation ===
def select_utxos_for_payment(amount, fee):
    selected = []
    total = 0
    for utxo in utxo_pool:  # BUG: iterates ALL UTXOs including inscriptions
        if total >= amount + fee:
            break
        selected.append(utxo)
        total += utxo.value
    return selected

# User wants to pay 0.6 BTC
selected = select_utxos_for_payment(amount=0.6 BTC, fee=0.001 BTC)
# selected = [abc:0 (0.5 BTC), def:0 (546 sats), ghi:0 (0.3 BTC)]
#                                ^^^^^^^^^^^^^^^^
#                                INSCRIPTION UTXO INCLUDED!

tx = create_transaction()
for utxo in selected:
    tx.add_input(utxo)
tx.add_output(address=recipient, value=0.6 BTC)
tx.add_output(address=change, value=0.1999 BTC)
sign_and_broadcast(tx)

# Result: inscription from def:0 is now at the recipient's address
# Ordinal theory assigns sats in input order → the 546 sats from def:0
# are among the first sats in the merged input, and they end up in the
# first output (recipient) based on sat ordering rules.
# The rare sat or BRC-20 transfer inscription is accidentally sent to the recipient.
```

**Why it works:** Without cardinal/ordinal UTXO separation, the wallet treats all UTXOs as fungible. Ordinal theory tracks individual satoshis through transactions, so spending an inscription-bearing UTXO transfers the inscription to whichever output receives the inscribed satoshi.

**Mitigation:** Maintain separate cardinal and ordinal UTXO pools. Never select ordinal UTXOs for non-inscription operations. Scan all incoming UTXOs against an indexer before adding to the cardinal pool.

---

## 3. BRC-20 Double-Spend via Indexer Lag

**Related checkpoints:** 0x0005, 0x0006

**Vulnerability:** A seller exploits the lag between an on-chain BRC-20 transfer and the indexer's state update to sell the same BRC-20 balance on two different marketplaces simultaneously.

```
# Seller has 1000 ORDI (BRC-20 balance)
# Step 1: Seller inscribes a transfer inscription for 500 ORDI
transfer_inscription_A = inscribe({
    "p": "brc-20", "op": "transfer", "tick": "ordi", "amt": "500"
})
# This inscription is now "pending" — inscribed but not yet sent

# Step 2: Seller inscribes ANOTHER transfer inscription for 500 ORDI
transfer_inscription_B = inscribe({
    "p": "brc-20", "op": "transfer", "tick": "ordi", "amt": "500"
})
# Both inscriptions are valid — each transfers 500 of the 1000 balance

# Step 3: Seller lists transfer_A on Marketplace Alpha
# Step 4: Seller lists transfer_B on Marketplace Beta
# Both marketplaces query their indexers — both show 1000 ORDI balance

# === Race condition ===
# Buyer on Alpha completes purchase of transfer_A
# Buyer on Beta completes purchase of transfer_B (nearly simultaneously)

# If both transactions confirm in the same block:
# - transfer_A is valid (sends 500 ORDI to buyer A)
# - transfer_B is valid (sends 500 ORDI to buyer B)
# Total: 1000 ORDI sold, seller received payment from both — NO double-spend here

# BUT: If seller only had 600 ORDI:
transfer_inscription_A = inscribe({"p":"brc-20","op":"transfer","tick":"ordi","amt":"500"})
transfer_inscription_B = inscribe({"p":"brc-20","op":"transfer","tick":"ordi","amt":"500"})
# Both are valid at inscription time (600 >= 500)
# Available balance after first pending transfer: 600 - 500 = 100
# Second transfer inscription requests 500 but available is only 100
# Consensus rule: second transfer inscription is INVALID (insufficient balance)
# BUT: a lagging indexer may not have processed the first inscription yet
# and shows 600 available, accepting the second transfer as valid

# Marketplace Beta completes the trade based on stale indexer state
# Buyer B pays but receives an INVALID transfer inscription — worthless
```

**Why it works:** BRC-20 balance is not enforced at the Bitcoin protocol level — it exists only in the indexer's interpretation of inscription data. If the indexer has not processed the first transfer inscription when the second one is validated, the marketplace accepts an invalid transfer. The seller receives payment, but the buyer gets a worthless inscription.

**Mitigation:** Cross-reference multiple indexers. Account for pending (inscribed but unsent) transfer inscriptions when computing available balance. Enforce minimum confirmation depth before accepting BRC-20 transfers as valid.

---

## 4. Runes Runestone Manipulation — Cenotaph Token Burn

**Related checkpoint:** 0x0007

**Vulnerability:** A malformed Runestone (the OP_RETURN data structure encoding Runes operations) is treated as a "cenotaph" by the Runes protocol — all Runes in the transaction's inputs are burned (assigned to the special null rune, making them unrecoverable). A marketplace that constructs or accepts malformed Runestones can accidentally or maliciously burn user tokens.

```
# Valid Runestone structure (simplified)
# OP_RETURN OP_13 <varint-encoded tag-value pairs> <edicts>
# Tags must be in ascending order, varints must be canonical

# === Valid Runestone: transfer 100 RUNE_X to output 2 ===
valid_runestone = encode_runestone(
    edicts=[
        Edict(rune_id=RUNE_X, amount=100, output=2)
    ]
)
tx.add_output(script=OP_RETURN || OP_13 || valid_runestone, value=0)
# Result: 100 RUNE_X transferred to output at index 2

# === Malformed Runestone: out-of-order tags → cenotaph ===
malformed_data = bytes([
    0x04, 0x01,  # tag 4 (body) first
    0x02, 0x05,  # tag 2 (pointer) second — ERROR: tag 2 < tag 4, not ascending
])
tx.add_output(script=OP_RETURN || OP_13 || malformed_data, value=0)
# Consensus parser detects out-of-order tags → CENOTAPH
# ALL Runes in transaction inputs are BURNED

# === Marketplace constructs a trade transaction ===
trade_tx = create_transaction()
trade_tx.add_input(utxo=seller_runes_utxo)  # contains 1000 RUNE_X
trade_tx.add_input(utxo=buyer_funding)
trade_tx.add_output(address=seller, value=0.1 BTC)     # payment
trade_tx.add_output(address=buyer, value=546 sats)      # Runes destination

# Platform constructs Runestone with a bug in tag encoding
runestone = platform_encode_runestone(
    edicts=[Edict(rune_id=RUNE_X, amount=1000, output=1)]
)
# Bug: platform uses non-canonical varint for amount (5 bytes instead of 2)
# OR: platform includes duplicate tags
# OR: platform uses unknown flag that triggers cenotaph

trade_tx.add_output(script=OP_RETURN || OP_13 || runestone, value=0)
broadcast(trade_tx)

# Result: Runestone is a cenotaph — 1000 RUNE_X are BURNED
# Seller received payment, buyer received empty UTXO with no Runes
```

**Why it works:** The Runes protocol has strict encoding rules for Runestones. Any violation (out-of-order tags, non-canonical varints, duplicate tags, unknown flags in certain positions) causes the entire Runestone to be interpreted as a cenotaph. Cenotaphs burn all Runes input to the transaction. A marketplace that does not use the canonical parser can construct cenotaphs accidentally.

**Mitigation:** Use the reference implementation's Runestone parser (from the `ord` codebase). Validate every Runestone for cenotaph conditions before broadcast. Implement a dry-run validation step that checks the transaction against the Runes consensus rules.

---

## 5. Fee Output Substitution in Buyer Completion

**Related checkpoints:** 0x0002, 0x000b

**Vulnerability:** When a buyer completes a listing PSBT, the seller's `SIGHASH_SINGLE|ANYONECANPAY` signature only commits to the seller's input and the seller's payment output. All other outputs (inscription delivery, platform fee, creator royalty, buyer change) are uncommitted and fully controlled by the buyer. A buyer can manipulate these outputs to skip fees, redirect royalties, or inflate their change.

```
# Seller's signed listing PSBT
seller_psbt = create_psbt()
seller_psbt.add_input(utxo=inscription_utxo, value=546 sats)    # input 0
seller_psbt.add_output(address=seller, value=0.1 BTC)            # output 0 (committed)
seller_sig = sign(seller_psbt, input_0, sighash=SIGHASH_SINGLE|ANYONECANPAY)

# === Honest buyer completion ===
honest_tx = seller_psbt.clone()
honest_tx.add_input(utxo=buyer_funding, value=0.2 BTC)          # input 1
honest_tx.add_output(address=buyer, value=546 sats)               # output 1: inscription
honest_tx.add_output(address=platform, value=0.005 BTC)          # output 2: platform fee (5%)
honest_tx.add_output(address=creator, value=0.005 BTC)           # output 3: royalty (5%)
honest_tx.add_output(address=buyer_change, value=0.0893 BTC)     # output 4: change
# fee = 0.2 + 0.000546 - 0.1 - 0.000546 - 0.005 - 0.005 - 0.0893 = ~0.0012 BTC

# === Malicious buyer completion (skips fees and royalties) ===
malicious_tx = seller_psbt.clone()
malicious_tx.add_input(utxo=buyer_funding, value=0.2 BTC)
malicious_tx.add_output(address=buyer, value=546 sats)            # inscription
malicious_tx.add_output(address=buyer_change, value=0.0993 BTC)  # all "savings" to change
# fee = 0.2 + 0.000546 - 0.1 - 0.000546 - 0.0993 = ~0.0012 BTC
# Seller's signature is still valid — it only commits to output 0 (seller payment)
# Platform fee: 0 BTC (skipped)
# Creator royalty: 0 BTC (skipped)
# Buyer saves 0.01 BTC
```

**Why it works:** `SIGHASH_SINGLE|ANYONECANPAY` commits only to the input being signed and the output at the same index. All other outputs are uncommitted. The buyer has full control over outputs at indices 1, 2, 3, etc. Without server-side validation, the buyer can construct any combination of outputs.

**Mitigation:** Server-side validation of completed transactions before broadcast — verify fee and royalty outputs are present with correct amounts. Alternatively, use a co-signing model where the platform adds its own `SIGHASH_ALL` signature after verifying the complete output set.

---

## 6. Inscription Destruction via Dust Limit Violation

**Related checkpoint:** 0x000e

**Vulnerability:** A marketplace transaction creates an inscription-bearing output with a value below the dust limit. Standard nodes reject the transaction, but if it reaches a non-standard miner, the output is created on-chain but may be unspendable by standard transactions. Alternatively, the transaction construction omits the inscription output entirely, and the inscription's satoshis are absorbed into the fee.

```
# Inscription on a P2WPKH output (dust limit: 546 sats)
inscription_utxo = { outpoint: "abc:0", value: 546 sats, has_inscription: true }

# === Scenario 1: Sub-dust inscription delivery ===
trade_tx = create_transaction()
trade_tx.add_input(inscription_utxo)                             # 546 sats
trade_tx.add_input(buyer_funding, value=0.1 BTC)                 # funding
trade_tx.add_output(address=seller, value=0.099 BTC)             # seller payment
trade_tx.add_output(address=buyer, value=330 sats)               # inscription to buyer
#                                    ^^^^^^^^
#                          Below P2WPKH dust limit (546 sats)!
#                          330 sats is P2TR dust limit, not P2WPKH

# Standard nodes reject this transaction: "dust" error on output 1
# If submitted to a non-standard miner:
# - Output is created but may be unspendable by standard wallets
# - Inscription is "trapped" in a sub-dust UTXO

# === Scenario 2: Missing inscription output ===
bad_trade_tx = create_transaction()
bad_trade_tx.add_input(inscription_utxo)                         # 546 sats
bad_trade_tx.add_input(buyer_funding, value=0.1 BTC)
bad_trade_tx.add_output(address=seller, value=0.1 BTC)           # seller payment
bad_trade_tx.add_output(address=buyer_change, value=0.0004 BTC)  # change
# NO inscription delivery output!
# fee = 546 + 10000000 - 10000000 - 40000 = 546 sats
# The inscription's 546 sats become part of the fee
# The inscribed satoshi goes to the miner — inscription is effectively destroyed

# === Scenario 3: Dust limit mismatch across script types ===
# P2TR dust limit: 330 sats
# P2WPKH dust limit: 546 sats
# P2SH dust limit: 540 sats
# P2PKH dust limit: 546 sats

# Marketplace assumes P2TR (330 sats) but buyer provides P2WPKH address
trade_tx.add_output(address=buyer_p2wpkh, value=330 sats)  # below 546-sat P2WPKH limit
# Transaction rejected by standard nodes
```

**Why it works:** Dust limits vary by output script type. If the marketplace does not match the dust threshold to the specific output script type being created, it may construct transactions that are rejected by standard nodes or create unspendable outputs. Missing inscription outputs cause the inscription's satoshis to be absorbed into the fee, permanently destroying the inscription.

**Mitigation:** Validate all outputs against the correct dust limit for their script type before broadcast. Always create an explicit inscription delivery output with at least the appropriate dust limit value. Enforce minimum listing prices that accommodate dust requirements.
