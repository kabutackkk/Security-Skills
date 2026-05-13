# Slashing Mechanism and Finality Gadget Reference

This document covers EOTS (Extractable One-Time Signatures) mechanics, equivocation detection, slashing transaction construction, false positive analysis, and comparison with PoS slashing. It supports checkpoints 0x0003, 0x0004, 0x0005, and 0x0006 in the main SKILL.md checklist.

---

## 1. EOTS (Extractable One-Time Signatures) Mechanics

### 1.1 Overview

EOTS is a Schnorr signature variant where the signing key is designed for one-time use. The critical property: if the same EOTS key signs two different messages, the private key can be algebraically extracted from the two signatures.

In BTC staking, EOTS provides the slashing mechanism:
- A validator's EOTS key is bound to a specific block height on the PoS chain.
- The validator signs exactly one block at that height with their EOTS key.
- If the validator equivocates (signs two conflicting blocks at the same height), both signatures are public.
- Anyone can extract the EOTS private key from the two signatures.
- The extracted key is used to execute a pre-signed slashing transaction.

### 1.2 Mathematical Foundation

```
# Standard Schnorr Signature
# Private key: x
# Public key:  P = x * G
# Nonce:       k (random per signature)
# Public nonce: R = k * G
# Message:     m
# Challenge:   e = H(R || P || m)
# Signature:   s = k + e * x  (mod n)

# === EOTS: One-Time Schnorr Signature ===
# The nonce k is FIXED for a given signing context (block height)
# k = EOTS_NonceGen(x, height)  — deterministic from private key and height
# This means: same key + same height → same R

# Signing message m1 at height h:
R = k * G                        # fixed for this height
e1 = H(R || P || m1)
s1 = k + e1 * x  (mod n)
signature_1 = (R, s1)

# Signing message m2 at the SAME height h (equivocation!):
R = k * G                        # SAME R — same nonce!
e2 = H(R || P || m2)
s2 = k + e2 * x  (mod n)
signature_2 = (R, s2)

# === Key Extraction ===
# Given: (R, s1, m1) and (R, s2, m2) with same R and same P
#
# s1 = k + e1 * x
# s2 = k + e2 * x
#
# s1 - s2 = (e1 - e2) * x
#
# x = (s1 - s2) * inverse(e1 - e2, n)  mod n
#
# Total cost: 1 subtraction + 1 modular inverse
# No brute force. No computational hardness. Pure algebra.

def extract_eots_key(R, P, m1, s1, m2, s2):
    """Extract EOTS private key from two signatures with same nonce."""
    assert m1 != m2, "Messages must be different for extraction"

    e1 = tagged_hash("BIP0340/challenge", R || P || m1)
    e2 = tagged_hash("BIP0340/challenge", R || P || m2)

    assert e1 != e2, "Challenges must differ"

    # x = (s1 - s2) / (e1 - e2) mod n
    x = ((s1 - s2) * mod_inverse(e1 - e2, SECP256K1_ORDER)) % SECP256K1_ORDER

    # Verify: x * G should equal P
    assert x * G == P, "Extracted key does not match public key"

    return x
```

### 1.3 EOTS Nonce Generation

The EOTS nonce must be deterministic per (key, height) pair to ensure that:
- Signing the same message twice at the same height produces identical signatures (safe re-signing).
- Signing different messages at the same height produces signatures with the same nonce (enables extraction on equivocation).

```
def eots_nonce_gen(private_key, height):
    """Generate a deterministic nonce for a given block height."""
    # The nonce is deterministic: same key + same height → same nonce
    # This is different from standard Schnorr where nonces MUST be random
    nonce_seed = tagged_hash("EOTS/nonce", private_key || height.to_bytes(8))
    k = int(nonce_seed) % SECP256K1_ORDER
    if k == 0:
        raise ValueError("Invalid nonce — height produces zero nonce")
    return k

# Usage:
k = eots_nonce_gen(validator_private_key, block_height=100)
R = k * G  # This R is the same for any message at height 100
```

**Security property:** The nonce `k` depends on the private key `x`, so an external observer cannot predict `k` from public information. But the deterministic binding ensures that the same key at the same height always produces the same `k` (and thus the same `R`).

---

## 2. Equivocation Detection

### 2.1 What Constitutes Equivocation

Equivocation in a PoS context means: a validator signs two conflicting proposals at the same block height. "Conflicting" means the proposals have different content (different block hashes, different transaction sets, etc.).

```
# Equivocation evidence structure
class EquivocationEvidence:
    validator_pubkey: bytes    # EOTS public key P
    height: int                # Block height where equivocation occurred
    signature_1: (R, s1)       # First signature
    message_1: bytes           # First signed block (or block hash)
    signature_2: (R, s2)       # Second signature (same R!)
    message_2: bytes           # Second signed block (different from message_1)

def verify_equivocation(evidence):
    """Verify that the evidence proves equivocation."""
    P = evidence.validator_pubkey

    # 1. Messages must be different
    assert evidence.message_1 != evidence.message_2, "Same message is not equivocation"

    # 2. Both signatures must have the same public nonce R
    R1 = evidence.signature_1.R
    R2 = evidence.signature_2.R
    assert R1 == R2, "Different nonces — not EOTS equivocation"

    # 3. Both signatures must be valid under the same public key
    assert verify_schnorr(P, evidence.message_1, evidence.signature_1), "Signature 1 invalid"
    assert verify_schnorr(P, evidence.message_2, evidence.signature_2), "Signature 2 invalid"

    # 4. Extract the private key
    x = extract_eots_key(
        R1, P,
        evidence.message_1, evidence.signature_1.s,
        evidence.message_2, evidence.signature_2.s
    )

    # 5. Verify extracted key matches public key
    assert x * G == P, "Extracted key mismatch"

    return x  # Return extracted private key for slashing
```

### 2.2 Detection Pipeline

```
┌─────────────────────┐
│  PoS Chain Block     │
│  Production          │
│                      │
│  Validators sign     │
│  blocks at each      │
│  height              │
└─────────┬────────────┘
          │
          v
┌─────────────────────┐
│  Equivocation        │
│  Monitor             │
│                      │
│  Watches for two     │
│  valid signatures    │
│  at same height      │
│  from same validator │
└─────────┬────────────┘
          │ Equivocation detected
          v
┌─────────────────────┐
│  Evidence            │
│  Construction        │
│                      │
│  Packages two        │
│  conflicting sigs    │
│  as evidence         │
└─────────┬────────────┘
          │
          v
┌─────────────────────┐
│  EOTS Key            │
│  Extraction          │
│                      │
│  x = (s1-s2) /      │
│      (e1-e2) mod n   │
└─────────┬────────────┘
          │ Private key extracted
          v
┌─────────────────────┐
│  Slashing Tx         │
│  Execution           │
│                      │
│  Use extracted key   │
│  to complete and     │
│  broadcast slashing  │
│  transaction         │
└─────────┬────────────┘
          │
          v
┌─────────────────────┐
│  Staked BTC          │
│  Burned/Redistributed│
└─────────────────────┘
```

### 2.3 Time Budget for Detection and Slashing

| Phase | Time Estimate | Notes |
|-------|--------------|-------|
| Equivocation occurs | T=0 | Validator signs two conflicting blocks |
| Detection by monitor | T + 1-10 blocks (PoS) | Depends on PoS block time and monitoring coverage |
| Evidence propagation | T + 1-30 min | Evidence must reach the Bitcoin-side slashing system |
| Key extraction | T + <1 sec | Algebraic computation, nearly instant |
| Slashing tx construction | T + <1 min | Completing the pre-signed transaction with extracted key |
| Slashing tx broadcast | T + 1 min | Submitting to Bitcoin mempool |
| Slashing tx confirmation | T + 10-60 min | Depends on fee rate and Bitcoin congestion |
| **Total worst case** | **~2 hours** | With margin for delays |
| **Unbonding period** | **>>2 hours** | Must be significantly longer (e.g., 3 days / 432 blocks) |

---

## 3. Slashing Transaction Construction

### 3.1 Pre-Signed Slashing Transaction

The slashing transaction is pre-signed as part of the staking covenant setup. It is partially complete — it requires the EOTS private key (or a signature from the EOTS key) to finalize.

```
# === Slashing Transaction (pre-signed by staker) ===

# The staking output's slashing script leaf:
# <staker_pk> OP_CHECKSIGVERIFY <fp_pk> OP_CHECKSIGVERIFY <covenant_multisig>
# This requires: staker signature + FP signature + covenant committee signatures

# During covenant setup, the staker pre-signs the slashing transaction:

slashing_tx = Transaction(
    version = 2,
    inputs = [
        Input(
            outpoint = staking_txid:0,
            sequence = 0xFFFFFFFE,  # RBF enabled for fee bumping
        )
    ],
    outputs = [
        Output(
            value = slashing_amount,
            script = P2PKH(burn_address)  # or OP_RETURN for provable burn
        ),
        Output(
            value = staked_amount - slashing_amount - fee,
            script = P2TR(staker_return_address)  # remaining to staker
        ),
    ],
    locktime = 0,
)

# Staker signs the slashing transaction
staker_slashing_sig = sign_tapscript(
    slashing_tx,
    input_index = 0,
    leaf = slashing_script_leaf,
    key = staker_private_key,
)

# Covenant committee members sign the slashing transaction
covenant_sigs = []
for member in covenant_committee:
    sig = sign_tapscript(
        slashing_tx,
        input_index = 0,
        leaf = slashing_script_leaf,
        key = member.private_key,
    )
    covenant_sigs.append(sig)
    if len(covenant_sigs) >= COVENANT_QUORUM:
        break

# The finality provider (FP) signature is the one that requires the EOTS key
# This signature is NOT created during setup — it is created at slashing time
# using the extracted EOTS private key

# === At slashing time (after equivocation detection) ===

# Extract EOTS key from equivocation evidence
eots_private_key = extract_eots_key(evidence)

# Complete the slashing transaction with the FP signature
fp_slashing_sig = sign_tapscript(
    slashing_tx,
    input_index = 0,
    leaf = slashing_script_leaf,
    key = eots_private_key,  # extracted from equivocation!
)

# Assemble witness: staker_sig + fp_sig + covenant_sigs + script + control_block
slashing_tx.inputs[0].witness = [
    staker_slashing_sig,
    fp_slashing_sig,
    *covenant_sigs,
    slashing_script,
    control_block,
]

# Broadcast slashing transaction
broadcast(slashing_tx)
```

### 3.2 Slashing Rate and Output Structure

```
# Babylon-style slashing with configurable slashing rate

SLASHING_RATE = 0.10  # 10% of staked amount is burned

staked_amount = 1.0 BTC
slashing_amount = staked_amount * SLASHING_RATE  # 0.1 BTC burned
staker_return = staked_amount - slashing_amount - fee  # ~0.9 BTC returned

# Output 0: Burned amount (provably unspendable)
# Option A: OP_RETURN (most provable, but limited to 80 bytes)
burn_output_a = Output(value=0, script=OP_RETURN || "babylon_slash")
# Note: With OP_RETURN, the burned amount goes to fees (to miner)
# The actual burn is: miner receives extra fee equal to slashing_amount

# Option B: NUMS address (unspendable but output exists)
burn_output_b = Output(
    value=slashing_amount,
    script=P2TR(NUMS_BURN_ADDRESS)  # address with no known private key
)

# Output 1: Return remaining to staker
staker_output = Output(
    value=staker_return,
    script=P2TR(staker_withdrawal_address)
)
```

---

## 4. False Positive Analysis

### 4.1 Scenarios That Could Trigger False Slashing

| Scenario | Is It Equivocation? | Should It Slash? | How to Prevent False Positive |
|----------|-------------------|-----------------|-------------------------------|
| Validator signs block A, then re-signs block A after restart | No — same message signed twice | No | Same message → same signature (deterministic nonce) |
| Validator signs block A on partition 1, does NOT sign on partition 2 | No — only one signature exists | No | Detection requires TWO signatures |
| Validator signs block A, then signs block B at the same height | Yes — two different messages at same height | Yes | Genuine equivocation |
| Malicious peer fabricates a fake second signature | No — fake signature won't verify | No | Verification step rejects invalid signatures |
| Validator restarts and re-proposes a different block | Yes — software bug causes genuine equivocation | Yes (but unfair) | Signing guardrails: persistent height log |
| Clock drift causes validator to think it's a new height | Depends on drift magnitude | Potentially unfair | Sync clocks; use chain height not wall clock |

### 4.2 Safe Re-Signing

The EOTS nonce is deterministic per (key, height). This means signing the same message twice produces the SAME signature — not a second signature with the same nonce.

```
# Safe re-signing: same key + same height + same message
k = eots_nonce_gen(x, height=100)
R = k * G

e = H(R || P || block_hash_A)
s = k + e * x

# First signing:
signature_1 = (R, s)  # s = k + e * x

# Re-signing after restart (same message):
signature_2 = (R, s)  # IDENTICAL — same k, same e, same x → same s

# signature_1 == signature_2 → no equivocation evidence
# An observer cannot distinguish this from a network retransmission
```

### 4.3 Signing Guardrails

```
# === Validator Signing Guardrails ===
# Prevent accidental equivocation due to software bugs

class EOTSigner:
    def __init__(self, private_key, height_log_path):
        self.key = private_key
        self.height_log = PersistentStore(height_log_path)

    def sign(self, message, height):
        # Check if we've already signed at this height
        previous = self.height_log.get(height)

        if previous is not None:
            if previous.message == message:
                # Re-signing same message — return cached signature
                return previous.signature
            else:
                # DIFFERENT message at same height — REFUSE to sign
                raise EquivocationPrevention(
                    f"Already signed different message at height {height}. "
                    f"Signing this would be equivocation!"
                )

        # First time signing at this height — proceed
        k = eots_nonce_gen(self.key, height)
        R = k * G
        e = tagged_hash("BIP0340/challenge", R || self.pubkey || message)
        s = (k + e * self.key) % SECP256K1_ORDER
        signature = (R, s)

        # Persist the signing record BEFORE returning
        # Use fsync/flush to ensure durability
        self.height_log.put(height, SigningRecord(message, signature))
        self.height_log.flush()

        return signature
```

---

## 5. Comparison with PoS Slashing

| Property | BTC Staking (EOTS) | Ethereum PoS Slashing | Cosmos PoS Slashing |
|----------|-------------------|----------------------|---------------------|
| Slashing trigger | EOTS key extraction on equivocation | Attestation/proposal equivocation | Double signing, downtime |
| Enforcement | Pre-signed Bitcoin transaction | Smart contract on Ethereum | Protocol-level (Tendermint) |
| Trust model | Bitcoin consensus + covenant | Ethereum consensus | Cosmos chain consensus |
| Slashing asset | BTC (on Bitcoin) | ETH (on Ethereum) | Staking token (same chain) |
| Cross-chain | Yes (PoS chain ↔ Bitcoin) | No (same chain) | No (same chain) |
| Unbonding period | ~3 days (Babylon) | ~27 hours | 21 days (typical) |
| Can validator block slashing? | No (pre-signed tx + key extraction) | No (protocol-enforced) | No (protocol-enforced) |
| False positive risk | Low (cryptographic proof required) | Low (attestation database) | Medium (uptime-based) |
| Recovery from false slash | None (BTC is burned) | None (ETH is burned) | Governance proposal |

### Key Differences for Auditors

1. **BTC staking is cross-chain:** The slashing mechanism spans two chains (Bitcoin and PoS chain). Timing, finality, and communication delays between chains create a larger attack surface than same-chain slashing.

2. **BTC slashing is irreversible:** Burned BTC cannot be recovered through governance or social consensus (unlike some PoS chains where governance can reverse slashing). This makes false positive prevention critical.

3. **Pre-signed transactions are static:** Unlike smart contract slashing that can be upgraded, pre-signed slashing transactions are fixed at staking time. Protocol upgrades must maintain backward compatibility with existing pre-signed transactions (see checkpoint 0x000f).

4. **EOTS key extraction is non-interactive:** Anyone who observes equivocation can extract the key and execute slashing — there is no need for a validator committee vote or governance action. This is both a strength (cannot be censored) and a risk (no human review before execution).

---

## 6. Slashing Security Checklist

```
1. EOTS implementation correctness?
   │
   ├── Key extraction verified against test vectors → GOOD
   │
   └── No test vectors or custom implementation → FLAG
       Algebraic errors in extraction formula could cause
       false positives (extract wrong key) or false negatives (fail to extract)

2. Equivocation detection requires proof?
   │
   ├── Two valid signatures, same R, same P, different messages → GOOD
   │   All four conditions verified independently
   │
   └── Missing any condition → FLAG
       ├── No R comparison → could accept different-nonce sigs (not equivocation)
       ├── No message comparison → could accept same-message re-signs
       └── No signature verification → could accept fabricated evidence

3. Slashing transaction pre-signed before staking?
   │
   ├── Yes, fully constructed at covenant setup → GOOD
   │
   └── No, requires runtime construction → FLAG
       └── Depends on committee availability at slashing time?
           └── Committee can refuse → slashing not enforceable

4. Slashing executable without validator cooperation?
   │
   ├── Only requires extracted EOTS key + pre-existing signatures → GOOD
   │
   └── Requires validator's active participation → CRITICAL FLAG
       Validator can refuse to cooperate in their own slashing

5. Unbonding period > slashing pipeline time?
   │
   ├── Unbonding >> worst-case slashing time → GOOD
   │   (e.g., 432 blocks >> 12 blocks worst case)
   │
   └── Unbonding ≈ or < slashing time → CRITICAL FLAG
       Validators can outrun slashing by unbonding fast

6. Burn address provably unspendable?
   │
   ├── NUMS address with published derivation → GOOD
   ├── OP_RETURN output → GOOD (burns to fee)
   │
   └── Regular address → CRITICAL FLAG
       Someone holds the key to the "burn" address?
       └── Slashed funds are recoverable → slashing is meaningless
```
