# Ordinals Indexer Trust Model and Verification Guide

This document covers the trust assumptions inherent in relying on Ordinals/BRC-20/Runes indexers, common inconsistencies between indexers, verification approaches, and BRC-20 consensus edge cases. It supports checkpoints 0x0005 and 0x0006 in the main SKILL.md checklist.

---

## 1. The Indexer Trust Problem

Bitcoin's base protocol has no concept of inscriptions, BRC-20 tokens, or Runes balances. These are "metaprotocol" layers — conventions for interpreting Bitcoin transaction data that exist entirely in off-chain indexer software. The indexer is the source of truth for:

- Which satoshis bear inscriptions (ordinal tracking)
- BRC-20 token balances (inscription-based deploy/mint/transfer state machine)
- Runes balances (OP_RETURN-based Runestone parsing)
- Inscription content and metadata (envelope parsing)

**The critical trust assumption:** Any marketplace that displays inscription ownership, BRC-20 balances, or Runes holdings is implicitly trusting its indexer's interpretation of Bitcoin transaction data. If the indexer is wrong, the marketplace operates on false state.

---

## 2. Major Indexers and Their Differences

| Indexer | Maintained By | Coverage | Notes |
|---------|--------------|----------|-------|
| `ord` | Casey Rodarmor (Ordinals creator) | Ordinals, Runes | Reference implementation; defines canonical ordinal theory |
| `OPI` | Open community | BRC-20 | Focuses on BRC-20 indexing; may diverge from `ord` on edge cases |
| `Hiro Ordinals API` | Hiro (formerly Stacks) | Ordinals, BRC-20 | Commercial API; indexer implementation is separate from `ord` |
| `UniSat Indexer` | UniSat | BRC-20, Runes | Popular marketplace indexer; has had historical divergences |
| `Best-in-Slot` | Best-in-Slot | BRC-20 | BRC-20-focused; tracks consensus vs non-consensus interpretations |

### Known Divergence Areas

1. **Inscription numbering:** Different indexers may assign different inscription numbers to the same inscription due to indexing order or handling of edge cases (e.g., inscriptions in coinbase transactions).

2. **BRC-20 tick case sensitivity:** Early BRC-20 implementations disagreed on whether tick symbols are case-sensitive. The consensus settled on case-insensitive comparison (4-byte tick, case-folded), but some indexers had periods where they treated ticks as case-sensitive.

3. **Cursed inscriptions:** Inscriptions that violate certain rules (e.g., inscriptions in non-first input, inscriptions with non-standard envelopes) are "cursed" and receive negative inscription numbers. Not all indexers handle cursed inscriptions identically.

4. **BRC-20 self-transfer behavior:** Whether a BRC-20 transfer inscription sent back to the same address is valid or treated as a burn varies across early indexer implementations.

5. **Runes cenotaph edge cases:** Specific malformed Runestone patterns may be classified differently by different parsers — one parser's valid Runestone may be another's cenotaph.

---

## 3. Indexer Verification Approaches

### 3.1 Cross-Indexer Verification

Query multiple independent indexers and compare results before executing trades.

```
def verify_inscription_ownership(inscription_id, expected_owner):
    # Query multiple indexers
    ord_result = query_ord_indexer(inscription_id)
    hiro_result = query_hiro_api(inscription_id)
    unisat_result = query_unisat_api(inscription_id)

    owners = [ord_result.owner, hiro_result.owner, unisat_result.owner]

    # All indexers must agree
    if len(set(owners)) != 1:
        raise IndexerDisagreement(
            f"Indexers disagree on ownership of {inscription_id}: {owners}"
        )

    if owners[0] != expected_owner:
        raise OwnershipMismatch(
            f"Expected owner {expected_owner}, indexers report {owners[0]}"
        )

    return True
```

**Limitations:** Cross-indexer verification detects disagreements but does not determine which indexer is correct. It also requires that at least one indexer is always accurate.

### 3.2 UTXO-Level Verification

Verify that the inscription-bearing UTXO is still unspent at the expected address by querying Bitcoin full nodes directly.

```
def verify_utxo_unspent(inscription_id, indexer):
    # Get the UTXO that the indexer claims holds this inscription
    inscription_data = indexer.get_inscription(inscription_id)
    utxo_outpoint = inscription_data.outpoint  # txid:vout

    # Query a Bitcoin full node for the UTXO set
    utxo = bitcoin_rpc.gettxout(utxo_outpoint.txid, utxo_outpoint.vout)

    if utxo is None:
        raise UTXOSpent(
            f"UTXO {utxo_outpoint} is already spent — inscription has been transferred"
        )

    # Verify the scriptPubKey matches the expected owner
    if utxo.scriptPubKey.address != inscription_data.owner:
        raise OwnerMismatch(
            f"UTXO address {utxo.scriptPubKey.address} != expected {inscription_data.owner}"
        )

    return True
```

**Key insight:** Even if an indexer correctly identifies the inscription's current UTXO, the UTXO may have been spent in a very recent (unconfirmed or recently confirmed) transaction that the indexer has not yet processed. Always check UTXO status against a full node.

### 3.3 Sat-Level Verification (Deep Verification)

Trace the specific satoshi bearing the inscription through all transactions from the inscription genesis to the current UTXO, verifying that ordinal tracking rules were applied correctly.

```
def trace_inscription_sat(inscription_id, genesis_txid, genesis_output_index):
    # Start from the genesis transaction (where the inscription was created)
    current_txid = genesis_txid
    current_vout = genesis_output_index

    # Determine which satoshi within the genesis output bears the inscription
    # (first-in-first-out sat ordering)
    sat_offset = 0  # inscription is on the first sat of the output by convention

    while True:
        # Check if this UTXO is still unspent
        utxo = bitcoin_rpc.gettxout(current_txid, current_vout)
        if utxo is not None:
            # UTXO is unspent — this is the current location of the inscription
            return { "outpoint": f"{current_txid}:{current_vout}", "owner": utxo.address }

        # UTXO was spent — find the spending transaction
        spending_tx = find_spending_tx(current_txid, current_vout)

        # Track the sat through the spending transaction using ordinal theory
        # Sats flow through inputs to outputs in first-in-first-out order
        input_sats_before = sum(
            get_output_value(inp.txid, inp.vout)
            for inp in spending_tx.inputs
            if (inp.txid, inp.vout) < (current_txid, current_vout)  # inputs before ours
        )
        sat_position = input_sats_before + sat_offset

        # Find which output this sat lands in
        output_sats = 0
        for i, output in enumerate(spending_tx.outputs):
            if output_sats + output.value > sat_position:
                current_txid = spending_tx.txid
                current_vout = i
                sat_offset = sat_position - output_sats
                break
            output_sats += output.value
        else:
            # Sat was consumed as fee — inscription is destroyed
            raise InscriptionDestroyed(f"Inscription sat consumed as fee in {spending_tx.txid}")
```

**Note:** Sat-level verification is computationally expensive but provides the strongest guarantee of inscription location. It is the same algorithm that indexers run, so it serves as an independent verification of the indexer's output.

---

## 4. BRC-20 Consensus Edge Cases

### 4.1 The Two-Step Transfer Model

BRC-20 transfers require two steps:

```
Step 1: INSCRIBE a transfer inscription
  → This "earmarks" the amount from the sender's available balance
  → The amount becomes "transferable" (deducted from "available", added to "transferable")

Step 2: SEND the transfer inscription (spend the UTXO containing it)
  → The recipient's available balance increases by the transfer amount
  → The sender's transferable balance decreases
```

**Edge cases in the two-step model:**

| Scenario | Consensus Rule | Common Indexer Bug |
|----------|---------------|-------------------|
| Transfer inscription sent to self | Valid — balance moves from "transferable" to "available" for the same address | Some indexers treat as no-op or burn |
| Transfer inscription spent as fee (no explicit recipient output) | Transfer is invalid — balance returns to sender's available | Some indexers treat as burn |
| Multiple transfer inscriptions for same tick in one transaction | Each is independent; processed in inscription number order | Some indexers only process the first |
| Transfer amount exceeds available balance at inscription time | Transfer inscription is invalid from creation | Lagging indexers may accept it temporarily |
| Transfer inscription in a transaction that also contains a mint | Both operations are valid; processed in inscription number order | Order-dependency bugs |

### 4.2 BRC-20 Balance Computation

```
def compute_brc20_balance(address, tick):
    # Process ALL inscriptions for this tick in inscription number order
    all_inscriptions = indexer.get_all_inscriptions_for_tick(tick)
    all_inscriptions.sort(by=inscription_number)

    balances = {}  # address → { available, transferable }

    for insc in all_inscriptions:
        if insc.op == "deploy":
            # Only the first valid deploy matters
            if tick not in deployed_ticks:
                deployed_ticks[tick] = { max: insc.max, lim: insc.lim, minted: 0 }

        elif insc.op == "mint":
            deploy = deployed_ticks.get(tick)
            if deploy is None:
                continue  # tick not deployed yet — invalid mint
            mint_amount = min(insc.amt, deploy.lim, deploy.max - deploy.minted)
            if mint_amount <= 0:
                continue  # over supply or over limit — invalid
            deploy.minted += mint_amount
            balances.setdefault(insc.owner, {"available": 0, "transferable": 0})
            balances[insc.owner]["available"] += mint_amount

        elif insc.op == "transfer":
            sender = insc.inscriber_address
            bal = balances.get(sender, {"available": 0, "transferable": 0})
            if insc.amt > bal["available"]:
                continue  # insufficient available balance — INVALID transfer inscription
            bal["available"] -= insc.amt
            bal["transferable"] += insc.amt

            # Now track the SEND step
            if insc.is_sent:  # the UTXO containing this inscription was spent
                recipient = insc.sent_to_address
                bal["transferable"] -= insc.amt
                balances.setdefault(recipient, {"available": 0, "transferable": 0})
                balances[recipient]["available"] += insc.amt
            # If not sent, amount remains in sender's "transferable" pool

    return balances.get(address, {"available": 0, "transferable": 0})
```

### 4.3 Common Indexer Bugs to Watch For

1. **Tick normalization:** BRC-20 ticks must be exactly 4 bytes. Ticks shorter than 4 bytes are invalid. Case sensitivity must follow consensus rules (case-insensitive comparison since the "jubilee" update).

2. **Amount precision:** BRC-20 amounts are represented as strings in the JSON payload. Amounts with more than 18 decimal places should be rejected. Amounts with leading zeros (e.g., `"00100"`) should be parsed correctly or rejected based on consensus rules.

3. **Self-transfer validity:** A transfer inscription sent from address A to address A should move the amount from "transferable" back to "available." This is a valid operation, not a no-op.

4. **Inscription in non-first input:** BRC-20 inscriptions in non-first inputs of a transaction are "cursed" inscriptions. The consensus handling of cursed BRC-20 inscriptions has changed over time and varies between indexers.

5. **Concurrent pending transfers:** When computing available balance, ALL pending (inscribed but unsent) transfer inscriptions must be deducted from available balance. A marketplace that only queries "available balance" without accounting for pending transfers enables over-spending.

---

## 5. Marketplace Verification Checklist

For auditors reviewing marketplace indexer integration:

```
1. Single indexer dependency?
   │
   ├── Yes → FLAG: Single point of failure
   │         Recommendation: Cross-reference at least 2 independent indexers
   │
   └── No → Verify disagreement handling:
            ├── Do both indexers agree? → Proceed
            └── Disagreement? → Halt trade, alert operators

2. Indexer freshness verification?
   │
   ├── Does the marketplace check the indexer's block height? → Good
   │   └── Is the indexer within 1-2 blocks of chain tip? → Acceptable
   │
   └── No freshness check? → FLAG: Stale state risk
       The indexer could be minutes or hours behind, showing outdated ownership

3. UTXO verification against full node?
   │
   ├── Yes → Good. Confirms the UTXO is unspent independently of the indexer
   │
   └── No → FLAG: Cannot detect recently transferred inscriptions
       The indexer may show ownership that is no longer valid on-chain

4. BRC-20 pending transfer accounting?
   │
   ├── Deducts pending transfers from available balance? → Good
   │
   └── Shows raw available balance without pending deductions? → FLAG
       Enables double-spending via multiple pending transfer inscriptions

5. Runes parser validation?
   │
   ├── Uses canonical parser (ord reference)? → Good
   │
   └── Custom parser? → FLAG: Cenotaph divergence risk
       Custom parsers may disagree with consensus on edge cases,
       showing Runes balances that do not exist on-chain

6. Reorg handling?
   │
   ├── Monitors for chain reorgs and re-indexes? → Good
   │   └── Halts trading during reorg? → Best practice
   │
   └── No reorg handling? → FLAG: Reorg-based double-spend risk
       Inscriptions transferred in orphaned blocks revert to previous owner
```

---

## 6. Trust Model Summary

| Component | Trust Level | Verification Approach |
|-----------|------------|----------------------|
| Bitcoin full node UTXO set | Highest (consensus-enforced) | `gettxout` RPC — UTXO is unspent or not |
| `ord` reference indexer | High (defines ordinal theory) | Cross-reference with other indexers |
| Third-party indexer APIs | Medium (implementation may diverge) | Cross-reference with `ord` and UTXO verification |
| Marketplace internal indexer | Lowest (custom code, potential bugs) | Independent audit + cross-reference with multiple external indexers |
| BRC-20 balance state | Medium (depends on indexer consensus rules) | Cross-indexer verification + pending transfer accounting |
| Runes balance state | High (if using canonical parser) | Validate against `ord` reference parser |

**Key principle:** The only ground truth on Bitcoin is the UTXO set maintained by full nodes. Everything above that (ordinal tracking, BRC-20 balances, Runes state) is an interpretation layer. Marketplaces must verify interpretations against multiple sources and anchor trust in the UTXO set wherever possible.
