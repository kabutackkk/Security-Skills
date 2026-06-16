# Timelock Safety Budget Reference

Complete reference for Lightning Network timelock engineering, safety budget calculation, L1/L2 coordination, and auditor decision guidance. Covers CLTV, CSV, anchor outputs, and submarine/reverse swap timelock coordination.

---

## 1. Safety Budget Framework

The "safety budget" is the margin between the earliest an HTLC can be claimed/refunded and the latest it must be enforced on-chain. Every HTLC forwarding hop and every swap protocol must account for these components:

### Budget Components

| Component | Symbol | Typical Range | Description |
|-----------|--------|--------------|-------------|
| Block variance | `B_var` | 1–6 blocks | Variance in block production time (Poisson process, ~10 min avg) |
| Fee spike congestion | `B_fee` | 6–72 blocks | Time to get a transaction confirmed during congestion; depends on fee budget |
| Propagation delay | `B_prop` | 1–2 blocks | Time for a transaction to propagate across the network and enter mempools |
| Monitoring latency | `B_mon` | 1–6 blocks | Time between breach/event and watchtower/node detection |
| Confirmation depth | `B_conf` | 3–6 blocks | Minimum confirmations before treating on-chain settlement as final |
| Chain reorg buffer | `B_reorg` | 6–12 blocks | Buffer for potential chain reorganizations |

### Safety Budget Formula

```
safety_budget = B_var + B_fee + B_prop + B_mon + B_conf + B_reorg

Minimum (optimistic):  1 + 6 + 1 + 1 + 3 + 6  = 18 blocks (~3 hours)
Recommended (normal):  3 + 18 + 1 + 3 + 6 + 6  = 37 blocks (~6 hours)
Conservative (adversarial): 6 + 72 + 2 + 6 + 6 + 12 = 104 blocks (~17 hours)
```

### Per-Hop CLTV Delta

Each forwarding hop in an LN route must subtract its `cltv_expiry_delta` to ensure it has enough time to enforce the HTLC on-chain if the downstream hop fails.

```
# BOLT #2 recommendation: cltv_expiry_delta >= 34 blocks (default in many implementations)
# This must be >= safety_budget for the hop

hop_cltv_delta >= B_var + B_fee + B_prop + B_mon + B_conf

# For a route: Alice → Bob → Carol → Dave
# Alice's outgoing HTLC: cltv_expiry = current_height + sum(all downstream deltas) + final_delta
# Bob's outgoing HTLC:   cltv_expiry = Alice_cltv - Bob_delta
# Carol's outgoing HTLC: cltv_expiry = Bob_cltv - Carol_delta
# Dave receives:         cltv_expiry = Carol_cltv - Dave_delta (= final_cltv_expiry)

# CRITICAL: Each hop must have its own safety budget.
# If Bob's delta is too small, Bob cannot enforce the timeout on-chain
# before Alice's upstream HTLC expires — Bob loses the HTLC value.
```

---

## 2. L1/L2 Timelock Coordination

### Submarine Swap (On-chain → Lightning)

User pays on-chain, receives Lightning payment. Service holds the preimage.

```
Timeline:
├── T0: User funds on-chain HTLC (locked to payment_hash, user refund at T_refund)
├── T1: Service sends LN payment to user (LN invoice expires at T_ln_expiry)
├── T2: User settles LN invoice (reveals preimage on LN)
├── T3: Service claims on-chain HTLC using preimage
└── T_refund: User can claim on-chain refund (if service never claimed)

Constraint: T_refund > T_ln_expiry + safety_budget

Formulas:
  T_ln_expiry  = T0 + ln_payment_timeout
  T_refund     = T_ln_expiry + safety_budget
  safety_budget >= B_fee + B_conf + B_reorg

Example:
  T0 = block 850,000
  ln_payment_timeout = 100 blocks
  safety_budget = 72 blocks
  T_ln_expiry = 850,100
  T_refund = 850,172

Violation check:
  IF T_refund <= T_ln_expiry:
    CRITICAL — user can refund while LN payment is still in-flight
  IF T_refund - T_ln_expiry < 18:
    WARNING — insufficient safety margin for adversarial conditions
```

### Reverse Swap (Lightning → On-chain)

User pays Lightning, receives on-chain BTC. User holds the preimage.

```
Timeline:
├── T0: User creates preimage and payment_hash
├── T1: Service locks on-chain HTLC to payment_hash (service refund at T_service_refund)
├── T2: User pays LN invoice (payment_hash, expires at T_ln_expiry)
├── T3: Service settles LN invoice (learns preimage)
├── T4: User claims on-chain HTLC using preimage
└── T_service_refund: Service can reclaim on-chain HTLC

Constraint: T_service_refund > T_ln_expiry + safety_budget
  AND: User must claim on-chain BEFORE T_service_refund

Formulas:
  T_ln_expiry      = T0 + ln_payment_timeout
  T_service_refund = T_ln_expiry + safety_budget
  user_claim_window = T_service_refund - T3 - B_conf

Critical race:
  IF service settles LN invoice (learns preimage at T3)
  AND simultaneously tries to claim on-chain refund at T_service_refund:
    Service could get BOTH the LN payment AND the on-chain refund
    IF T_service_refund - T3 < safety_budget

Violation check:
  IF T_service_refund <= T_ln_expiry:
    CRITICAL — service can refund on-chain while LN payment is in-flight
  IF user_claim_window < safety_budget:
    WARNING — user may not have enough time to claim on-chain
```

### Loop-In (On-chain → Channel Rebalance)

```
# Loop-In: user pays on-chain, service sends LN payment to user's channel
# Timelock ordering: on_chain_refund > ln_expiry + safety_budget
# Same as submarine swap coordination

loop_in_refund_timeout = ln_expiry + max(safety_budget, 2 * cltv_expiry_delta)
```

### Loop-Out (Channel → On-chain Rebalance)

```
# Loop-Out: user sends LN payment, service pays on-chain to user
# Timelock ordering: on_chain_service_refund > ln_expiry + safety_budget
# Same as reverse swap coordination

loop_out_refund_timeout = ln_expiry + max(safety_budget, 2 * cltv_expiry_delta)
```

---

## 3. CLTV vs CSV Usage Guide

### OP_CHECKLOCKTIMEVERIFY (CLTV) — BIP 65

Absolute timelock: transaction is invalid before a specific block height or Unix timestamp.

| Property | Detail |
|----------|--------|
| Comparison | `nLockTime >= cltv_value` |
| Domain | Block height (< 500M) or Unix timestamp (>= 500M) — domains must match |
| Use in LN | HTLC expiry (when the HTLC can be timed out) |
| Use in swaps | On-chain HTLC refund path (when the sender can reclaim funds) |
| Encoding | 5-byte little-endian integer in Script |

**LN-specific CLTV rules:**
- HTLC-timeout transactions use CLTV to enforce the expiry height
- Each forwarding hop subtracts its `cltv_expiry_delta`
- CLTV values in LN are ALWAYS block heights (never timestamps)
- BOLT #2 specifies minimum `cltv_expiry_delta` per channel

### OP_CHECKSEQUENCEVERIFY (CSV) — BIP 112

Relative timelock: transaction is invalid until N blocks/seconds after the input UTXO was confirmed.

| Property | Detail |
|----------|--------|
| Comparison | `nSequence >= csv_value` (relative to input confirmation) |
| Domain | Blocks (bit 22 = 0) or 512-second units (bit 22 = 1) |
| Disable flag | Bit 31 = 1 disables CSV; `nSequence = 0xFFFFFFFF` disables both CSV and nLockTime |
| Use in LN | `to_local` output delay (dispute window for penalty enforcement) |
| Use in LN | Second-stage HTLC transactions (delay after first-stage HTLC-success/timeout) |

**LN-specific CSV rules:**
- `to_self_delay` is negotiated per channel (BOLT #2, `open_channel`/`accept_channel`)
- Typical values: 144 blocks (1 day) to 2016 blocks (2 weeks)
- The CSV delay gives the counterparty time to detect and penalize a breach
- Second-stage HTLC transactions also have CSV delays

### Decision Guide: When to Use CLTV vs CSV

```
Is the deadline an absolute point in time (block height)?
├── yes → Use CLTV
│   Examples: HTLC expiry, swap refund timeout, invoice expiry enforcement
│
└── no → Is the deadline relative to when a transaction confirms?
    ├── yes → Use CSV
    │   Examples: to_local delay, second-stage HTLC delay, penalty window
    │
    └── no → Re-analyze the protocol — one of these must apply
```

---

## 4. The 500-Million Boundary

### Rule

```
IF cltv_value < 500,000,000:
    Interpreted as block height
    Transaction's nLockTime must also be < 500,000,000 (block height)
ELIF cltv_value >= 500,000,000:
    Interpreted as Unix timestamp
    Transaction's nLockTime must also be >= 500,000,000 (timestamp)

IF domains do not match → OP_CHECKLOCKTIMEVERIFY fails → script is unsatisfiable
```

### Audit Checks

1. **All CLTV values in LN contexts must be block heights (< 500M).** LN uses block heights exclusively. Any timestamp-domain CLTV value is a bug.

2. **Overflow check:** Verify that `current_height + delta` cannot exceed 499,999,999. At current block heights (~850,000) and realistic deltas (< 100,000), this is not reachable. But verify no arithmetic overflow or type confusion exists.

3. **Underflow check:** Verify that `cltv_expiry - delta` does not underflow to a negative value or wrap around in unsigned arithmetic.

4. **Type safety:** Verify that CLTV values are stored as unsigned 32-bit integers and that arithmetic operations check for overflow/underflow.

---

## 5. Anchor Outputs and CPFP Fee Bumping

### Problem

Force-close transactions have pre-signed fee rates that may be insufficient by the time they need to confirm. Without fee bumping capability, a force-close transaction can be stuck in the mempool indefinitely, preventing HTLC timeout enforcement.

### Anchor Output Mechanism (BOLT #3)

```
# Commitment transaction includes two anchor outputs (one per party):
anchor_output_local = {
    value: 330 sats,  # P2TR dust limit
    script: <local_pubkey> OP_CHECKSIG
            OP_IFDUP OP_NOTIF 16 OP_CHECKSEQUENCEVERIFY OP_ENDIF
}
# After 16 blocks, anyone can spend the anchor (cleanup)
# Before 16 blocks, only the local party can spend it (for CPFP)

# Fee bumping via CPFP:
cpfp_tx = create_tx(
    input=anchor_output,
    fee_rate=current_market_rate,  # High enough to bump the parent commitment tx
)
broadcast(cpfp_tx)
# Miners include both the commitment tx (low fee) and CPFP tx (high fee)
# because the combined fee rate exceeds their threshold
```

### Fee Budget Calculation

```
# Force-close fee budget must cover:
fee_budget = commitment_tx_fee + htlc_timeout_tx_fee + cpfp_fee

# Where:
commitment_tx_fee = commitment_tx_vsize * pre_signed_fee_rate
htlc_timeout_tx_fee = htlc_tx_vsize * pre_signed_fee_rate
cpfp_fee = (target_fee_rate - effective_rate) * (parent_vsize + child_vsize)

# Anchor output CPFP fee:
# Must compensate for the low pre-signed fee rate on the commitment tx
anchor_cpfp_fee = (target_fee_rate * (commit_vsize + cpfp_vsize)) - commitment_tx_fee

# Reserve requirement:
# The party must maintain a UTXO reserve sufficient for CPFP fee bumping
# under adversarial conditions (high fee environment)
min_reserve = max_expected_fee_rate * (commit_vsize + cpfp_vsize) * safety_multiplier
```

### Audit Checks for Fee Budgets

1. Verify the node maintains a UTXO reserve for CPFP fee bumping separate from channel funds
2. Check that the reserve is sized for adversarial fee conditions (100+ sat/vB)
3. Verify that anchor outputs are correctly constructed with the cleanup CSV path
4. Check that the CPFP transaction correctly references the anchor output
5. Verify fee estimation uses a robust source (not just a single mempool snapshot)

---

## 6. Timelock Auditor Decision Flowchart

```
Auditing a timelock value in LN dApp code?
│
├── Is it a CLTV (absolute) or CSV (relative) timelock?
│   ├── CLTV
│   │   ├── Is the value always < 500,000,000?
│   │   │   ├── yes → OK (block height domain)
│   │   │   └── no  → FLAG: potential 500M boundary violation (0x0004)
│   │   │
│   │   ├── Is the value derived from arithmetic (current_height + delta)?
│   │   │   ├── yes → Check for overflow and underflow
│   │   │   └── no  → Check source of the hardcoded value
│   │   │
│   │   └── Is this an HTLC expiry, swap refund, or invoice timeout?
│   │       ├── HTLC expiry → Verify cltv_expiry_delta >= safety_budget (0x0003)
│   │       ├── Swap refund → Verify ordering: refund_timeout > ln_expiry + safety_budget (0x0007, 0x0008)
│   │       └── Invoice timeout → Verify consistency with HTLC expiry chain
│   │
│   └── CSV
│       ├── Is this a to_self_delay (penalty window)?
│       │   ├── yes → Verify >= 144 blocks for mainnet; check if watchtower needs more (0x000c)
│       │   └── no  → Identify the purpose and verify adequacy
│       │
│       └── Is `nSequence` correctly set on the spending input?
│           ├── yes → Verify no conflict with nLockTime disable behavior
│           └── no  → FLAG: CSV will not be enforced (0x0005)
│
├── Is there a safety budget between related timelocks?
│   ├── yes → Verify budget >= 18 blocks (minimum) or 37+ blocks (recommended) (0x0003)
│   └── no  → FLAG: missing safety margin — race condition possible (0x0007, 0x0008)
│
├── Is the fee budget sufficient for on-chain enforcement within the timelock?
│   ├── yes → Verify fee estimation accounts for adversarial conditions (0x0009)
│   └── no  → FLAG: timelock may expire before on-chain tx confirms (0x0009)
│
└── Is there a watchtower or monitoring requirement within the timelock window?
    ├── yes → Verify watchtower uptime SLA covers the full dispute window (0x000c)
    └── no  → FLAG: no breach detection within penalty window (0x000c, 0x000d)
```

---

## 7. Common Timelock Misconfigurations

| Misconfiguration | Impact | Checkpoint |
|-----------------|--------|------------|
| `cltv_expiry_delta` too small (< 18 blocks) | Cannot enforce HTLC timeout on-chain before upstream expires | 0x0003 |
| Swap refund timeout <= LN invoice expiry | User can double-claim (refund + LN payment) | 0x0007 |
| Reverse swap refund timeout <= LN payment timeout | Service can double-claim (refund + preimage) | 0x0008 |
| `to_self_delay` too small (< 144 blocks) | Insufficient time for breach detection and penalty | 0x000c |
| No CPFP fee reserve for force-close | Commitment tx stuck in mempool; HTLC timeouts missed | 0x0009 |
| CLTV value crosses 500M boundary | Script unsatisfiable (permanent lock) or trivially satisfiable | 0x0004 |
| CSV delay disabled by `nSequence = 0xFFFFFFFF` | Penalty window eliminated; immediate claim by broadcaster | 0x000d |
| No confirmation depth check on swap settlement | Reorg can reverse settlement after preimage exposure | 0x000b |
