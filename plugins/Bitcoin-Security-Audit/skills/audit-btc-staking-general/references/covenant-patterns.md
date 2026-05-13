# Bitcoin Covenant Patterns for Staking

This document covers Bitcoin covenant construction patterns used in BTC staking protocols, including pre-signed transaction covenants, OP_CTV comparison, Babylon staking transaction structure, and unbonding flow diagrams. It supports checkpoints 0x0000, 0x0001, 0x0002, and 0x0007 in the main SKILL.md checklist.

---

## 1. What is a Bitcoin Covenant?

A covenant restricts how a UTXO can be spent — not just who can spend it (authentication) but what the spending transaction must look like (authorization of transaction structure). In traditional Bitcoin, once you have the private key for a UTXO, you can spend it to any output. A covenant adds the constraint: "you can spend this UTXO, but only to these specific outputs."

Bitcoin does not natively support covenants (as of 2025 — proposals like OP_CTV, OP_CAT, and OP_VAULT exist but are not activated). Staking protocols emulate covenants using pre-signed transactions.

---

## 2. Pre-Signed Transaction Covenants

### 2.1 How They Work

The staker creates a Taproot output (the staking output) with specific spending conditions. Before locking BTC in this output, the staker pre-signs a complete set of transactions that represent every allowed spending path. The staker then either:
- **Deletes the signing key** — no new transactions can be created for this output, so only the pre-signed transactions can spend it.
- **Distributes the key to a committee** — a threshold of committee members must cooperate to create any new transaction, adding a trust layer.

```
# === Pre-Signed Transaction Covenant Construction ===

# Step 1: Generate a one-time key for the staking output
staking_key = generate_key()
staking_pubkey = staking_key * G

# Step 2: Construct the staking output
# Taproot output with NUMS internal key (disable key path)
# Script tree contains leaves for: unbonding, slashing, emergency recovery
staking_output = TaprootOutput(
    internal_key = NUMS_POINT,  # no key-path spending
    script_tree = [
        Leaf(0, unbonding_script),   # OP_CSV <timelock> OP_DROP <staker_pubkey> OP_CHECKSIG
        Leaf(1, slashing_script),    # <eots_pubkey> OP_CHECKSIG (extractable on equivocation)
        Leaf(2, recovery_script),    # OP_CLTV <long_timelock> OP_DROP <staker_pubkey> OP_CHECKSIG
    ]
)

# Step 3: Construct pre-signed transactions for each spending path

# Unbonding transaction: spends staking output after timelock
unbonding_tx = Transaction(
    inputs  = [Input(outpoint=staking_txid:0, sequence=UNBONDING_TIMELOCK)],
    outputs = [Output(address=staker_withdrawal, value=staked_amount - fee)],
    locktime = 0
)
unbonding_sig = sign(unbonding_tx, input_0, script=unbonding_script, key=staking_key)

# Slashing transaction: spends staking output using EOTS key (after extraction)
slashing_tx = Transaction(
    inputs  = [Input(outpoint=staking_txid:0)],
    outputs = [Output(script=OP_RETURN, value=0),                    # burn marker
               Output(address=burn_address, value=staked_amount - fee)],  # burn
    locktime = 0
)
# This transaction is partially signed — it needs the EOTS private key to complete
# The EOTS key will only be available if the validator equivocates
slashing_partial_sig = sign(slashing_tx, input_0, script=slashing_script, key=staking_key)
# Note: the actual slashing_script may require BOTH staking_key and eots_key

# Emergency recovery transaction: spends staking output after long timelock
recovery_tx = Transaction(
    inputs  = [Input(outpoint=staking_txid:0, sequence=0xFFFFFFFF)],
    outputs = [Output(address=staker_recovery, value=staked_amount - fee)],
    locktime = RECOVERY_BLOCK_HEIGHT  # e.g., current_height + 52560 (~1 year)
)
recovery_sig = sign(recovery_tx, input_0, script=recovery_script, key=staking_key)

# Step 4: DELETE the staking key
# After all pre-signed transactions are created, the key is destroyed
# Only the pre-signed transactions can spend the staking output
secure_delete(staking_key)

# Step 5: Broadcast the staking transaction
staking_tx = Transaction(
    inputs  = [Input(outpoint=staker_utxo)],
    outputs = [staking_output],
)
sign_and_broadcast(staking_tx, key=staker_wallet_key)
```

### 2.2 Pre-Signed Covenant Limitations

| Limitation | Description | Mitigation |
|-----------|-------------|------------|
| **Key deletion trust** | No way to prove the key was deleted — the staker could secretly retain it | Covenant committee (threshold key), secure enclave |
| **Static output set** | Pre-signed transactions have fixed outputs — cannot adapt to new addresses or amounts | Include multiple pre-signed variants or use hash-locked flexibility |
| **No conditional logic** | Pre-signed transactions cannot evaluate conditions at spend time — they are fixed | Combine with Script conditions (timelocks, hash locks) |
| **Transaction pinning** | Pre-signed transactions have fixed fee rates — they may become unconfirmable during high-fee periods | Include CPFP output for fee bumping |
| **State explosion** | Complex protocols with many states require exponentially many pre-signed transactions | Minimize state machine, use committee for rare transitions |

---

## 3. OP_CTV vs Pre-Signed Transaction Comparison

`OP_CHECKTEMPLATEVERIFY` (OP_CTV, BIP-119) is a proposed opcode that would enable native covenants on Bitcoin. If activated, it would simplify staking covenant construction significantly.

```
# === Pre-Signed Transaction Covenant (current approach) ===

# Requires: key management, key deletion ceremony, covenant committee
# Trust model: trust that the key was deleted OR trust the committee
# Flexibility: cannot add new spending paths after setup

staking_output_presigned = TaprootOutput(
    internal_key = NUMS_POINT,
    script_tree = [
        Leaf(unbonding_script),  # requires staker key + timelock
        Leaf(slashing_script),   # requires EOTS key (extractable)
        Leaf(recovery_script),   # requires staker key + long timelock
    ]
)
# Plus: multiple pre-signed transactions, key deletion ceremony

# === OP_CTV Covenant (proposed, not yet activated) ===

# Requires: only Script construction — no key management
# Trust model: trust Bitcoin consensus (no third party)
# Flexibility: spending paths are consensus-enforced

staking_output_ctv = TaprootOutput(
    internal_key = NUMS_POINT,
    script_tree = [
        Leaf(
            # Unbonding path: enforces exact output structure
            OP_CSV <unbonding_timelock>
            OP_DROP
            OP_CTV <hash_of_unbonding_tx_template>
        ),
        Leaf(
            # Slashing path: enforces burn output
            <eots_pubkey> OP_CHECKSIGVERIFY
            OP_CTV <hash_of_slashing_tx_template>
        ),
        Leaf(
            # Recovery path: enforces return to staker after long delay
            OP_CLTV <recovery_height>
            OP_DROP
            OP_CTV <hash_of_recovery_tx_template>
        ),
    ]
)
# No key deletion needed — the spending conditions are in the Script itself
# No committee needed — Bitcoin consensus enforces the covenant
```

| Property | Pre-Signed Tx | OP_CTV |
|----------|--------------|--------|
| Trust model | Key deletion or committee | Bitcoin consensus |
| Key management | Complex (deletion, committee) | None |
| Spending path enforcement | Signed transactions (can be bypassed if key is retained) | Script-enforced (cannot be bypassed) |
| Fee flexibility | Fixed fee in pre-signed tx | Template can allow fee adjustment via additional inputs |
| Composability | Limited (static transactions) | High (Script-level, composable with other opcodes) |
| Availability | Now (no soft fork required) | Requires BIP-119 activation (not yet activated) |

---

## 4. Babylon Staking Transaction Structure

The Babylon protocol is the primary production implementation of BTC staking. Here is the detailed transaction structure:

### 4.1 Staking Transaction

```
Staking Transaction
├── Inputs
│   └── [Staker's BTC UTXOs]                    # Funded by the staker
│
├── Outputs
│   ├── Output 0: Staking Output (Taproot P2TR)
│   │   ├── Internal Key: NUMS (key path disabled)
│   │   └── Script Tree:
│   │       ├── Leaf 0: Timelock Path
│   │       │   └── <staking_time> OP_CSV OP_DROP
│   │       │       <staker_pk> OP_CHECKSIGVERIFY
│   │       │       <finality_provider_pk> OP_CHECKSIG
│   │       │
│   │       ├── Leaf 1: Unbonding Path
│   │       │   └── <staker_pk> OP_CHECKSIGVERIFY
│   │       │       <finality_provider_pk> OP_CHECKSIGVERIFY
│   │       │       <covenant_committee_multisig>
│   │       │
│   │       └── Leaf 2: Slashing Path
│   │           └── <staker_pk> OP_CHECKSIGVERIFY
│   │               <finality_provider_pk> OP_CHECKSIGVERIFY
│   │               <covenant_committee_multisig>
│   │
│   ├── Output 1: OP_RETURN (Staking Data)
│   │   └── OP_RETURN <babylon_tag> <version> <staker_pk> <fp_pk>
│   │       <staking_time> <tag_hash>
│   │
│   └── Output 2: Change (back to staker)
│       └── Staker's change address
```

### 4.2 Unbonding Transaction

```
Unbonding Transaction
├── Inputs
│   └── Input 0: Staking Output (via Unbonding Path / Leaf 1)
│       ├── Witness: <staker_sig> <fp_sig> <covenant_committee_sigs>
│       └── Spending Leaf 1 (Unbonding Path)
│
├── Outputs
│   └── Output 0: Unbonding Output (Taproot P2TR)
│       ├── Internal Key: NUMS (key path disabled)
│       └── Script Tree:
│           ├── Leaf 0: Timelock Withdraw Path
│           │   └── <unbonding_time> OP_CSV OP_DROP
│           │       <staker_pk> OP_CHECKSIG
│           │
│           └── Leaf 1: Slashing Path (during unbonding)
│               └── <staker_pk> OP_CHECKSIGVERIFY
│                   <finality_provider_pk> OP_CHECKSIGVERIFY
│                   <covenant_committee_multisig>
```

### 4.3 Slashing Transaction

```
Slashing Transaction
├── Inputs
│   └── Input 0: Staking Output or Unbonding Output (via Slashing Path)
│       ├── Witness: <staker_sig> <fp_sig> <covenant_committee_sigs>
│       └── Spending Slashing Path leaf
│
├── Outputs
│   ├── Output 0: Burn Output
│   │   └── <burn_address> (sent to protocol-defined burn address)
│   │       Amount: slashing_rate * staked_amount
│   │
│   └── Output 1: Change to Staker
│       └── <staker_address>
│           Amount: (1 - slashing_rate) * staked_amount - fee
```

### 4.4 Key Roles in Babylon

```
┌─────────────────────────────────────────────────────────────────┐
│                    Babylon Staking Roles                         │
├─────────────────┬───────────────────────────────────────────────┤
│ Staker          │ Locks BTC, signs pre-signed transactions,     │
│                 │ can initiate unbonding (with FP cooperation)  │
├─────────────────┼───────────────────────────────────────────────┤
│ Finality        │ Signs PoS blocks using EOTS key,              │
│ Provider (FP)   │ co-signs unbonding and slashing transactions, │
│                 │ equivocation reveals EOTS key                 │
├─────────────────┼───────────────────────────────────────────────┤
│ Covenant        │ Multi-sig committee that co-signs unbonding   │
│ Committee       │ and slashing transactions, prevents           │
│                 │ unauthorized spending                         │
├─────────────────┼───────────────────────────────────────────────┤
│ Covenant        │ Threshold: e.g., 6-of-9 committee members    │
│ Quorum          │ must sign for unbonding or slashing           │
└─────────────────┴───────────────────────────────────────────────┘
```

---

## 5. Unbonding Flow Diagram

```
                    ┌──────────────┐
                    │   STAKED     │
                    │  (Locked)    │
                    └──────┬───────┘
                           │
            ┌──────────────┴──────────────┐
            │                             │
      Unbonding Request              Equivocation
      (staker + FP +                 Detected
       covenant committee)
            │                             │
            v                             v
    ┌───────────────┐            ┌───────────────┐
    │  UNBONDING    │            │   SLASHED     │
    │  (Timelock    │            │  (BTC burned  │
    │   counting)   │            │   or redist.) │
    └───────┬───────┘            └───────────────┘
            │                             ^
            │                             │
            │   Equivocation during       │
            │   unbonding period ─────────┘
            │
            │ Unbonding timelock expires
            │ (OP_CSV satisfied)
            v
    ┌───────────────┐
    │  WITHDRAWABLE │
    │  (Staker can  │
    │   spend BTC)  │
    └───────┬───────┘
            │
            │ Staker spends
            v
    ┌───────────────┐
    │  WITHDRAWN    │
    │  (Complete)   │
    └───────────────┘


    Emergency Recovery (if all else fails):
    ┌──────────────┐     Long timelock     ┌───────────────┐
    │   STAKED     │ ──── expires ────────> │  RECOVERED    │
    │  (Locked)    │   (e.g., ~1 year)     │  (Staker      │
    └──────────────┘                        │   reclaims)   │
                                            └───────────────┘
```

---

## 6. Covenant Security Checklist

```
1. Internal key for staking output?
   │
   ├── NUMS point (provably unspendable) → GOOD
   │   Key path is disabled; all spending must go through script paths
   │
   └── Real key → CRITICAL FLAG
       Key holder can bypass ALL script conditions via key path
       └── Is it a multi-party key (MuSig2)? → MEDIUM (committee trust)
           Single party key → CRITICAL (unilateral bypass)

2. Pre-signed transaction set complete?
   │
   ├── Covers all state transitions → GOOD
   │   └── Verified against state machine diagram
   │
   └── Missing transitions → FLAG
       └── Missing unbonding → staker's BTC locked permanently
       └── Missing slashing → equivocation unpunishable
       └── Missing recovery → no fallback for protocol failure

3. Signing key handled securely?
   │
   ├── Key deleted after pre-signing → GOOD (if verifiable)
   │   └── Verifiable deletion? (secure enclave attestation)
   │       ├── Yes → Strong guarantee
   │       └── No → Trust assumption (staker could retain key)
   │
   ├── Distributed to covenant committee → ACCEPTABLE
   │   └── Threshold sufficient? (e.g., 6-of-9)
   │   └── Committee members independent?
   │   └── No single point of compromise?
   │
   └── Retained by staker → CRITICAL FLAG
       Staker can create unauthorized transactions at any time

4. Fee handling in pre-signed transactions?
   │
   ├── Fixed fee with CPFP bump output → GOOD
   │   Allows fee adjustment without changing the pre-signed transaction
   │
   ├── Fixed fee, no CPFP output → RISK
   │   If fee environment changes, transaction may be unconfirmable
   │
   └── Variable fee (requires new signature) → REQUIRES COMMITTEE
       Committee must be available to re-sign with updated fee

5. Timelock values appropriate?
   │
   ├── Unbonding timelock > 2x slashing evidence time → GOOD
   │
   ├── Recovery timelock > unbonding timelock → GOOD
   │   Recovery is a last resort, should have longest timelock
   │
   └── Any timelock < slashing evidence time → CRITICAL FLAG
       Validators can equivocate and withdraw before slashing
```
