# Vulnerable PSBT Construction Patterns

This document catalogs eight vulnerable PSBT construction patterns with pseudocode demonstrations. Each pattern corresponds to one or more checkpoints in the main SKILL.md checklist.

---

## 1. SIGHASH_NONE Output Theft

**Related checkpoint:** 0x0000

**Vulnerability:** A signer uses `SIGHASH_NONE`, which commits to zero outputs. Any party with access to the signed input can attach arbitrary outputs.

```
# Victim constructs and signs a PSBT input with SIGHASH_NONE
psbt = create_psbt()
psbt.add_input(utxo=victim_utxo, value=1.0 BTC)
psbt.add_output(address=merchant, value=0.5 BTC)
psbt.add_output(address=victim_change, value=0.4999 BTC)

# Victim signs with SIGHASH_NONE — signature does not commit to outputs
sig = sign_input(psbt, input_index=0, sighash=SIGHASH_NONE, key=victim_privkey)
psbt.set_signature(input_index=0, sig=sig)

# Attacker receives the signed PSBT, strips all outputs, adds their own
psbt.clear_outputs()
psbt.add_output(address=attacker, value=0.9999 BTC)

# Victim's signature is still valid — it committed to no outputs
finalize_and_broadcast(psbt)  # Attacker receives 0.9999 BTC
```

**Why it works:** `SIGHASH_NONE` (byte `0x02`) excludes all outputs from the signature hash. The signature remains valid regardless of what outputs are attached to the transaction.

---

## 2. SIGHASH_SINGLE Index Overflow (uint256(1) Bug)

**Related checkpoint:** 0x0001

**Vulnerability:** When `SIGHASH_SINGLE` is used on an input whose index exceeds the number of outputs, Bitcoin consensus returns `uint256(1)` as the sighash digest—a known constant that anyone can sign.

```
# Transaction with 3 inputs but only 2 outputs
tx.inputs  = [input_0, input_1, input_2]
tx.outputs = [output_0, output_1]

# Signing input_2 with SIGHASH_SINGLE
# Expected: sign commitment to output_2
# Actual: output_2 does not exist → sighash returns uint256(1)

sighash = compute_sighash(tx, input_index=2, flag=SIGHASH_SINGLE)
# sighash = 0x0000000000000000000000000000000000000000000000000000000000000001

# Anyone who knows the sighash is 1 can compute a valid signature
# Because the discrete log of a known hash can be brute-forced when the
# hash is a trivially small number, OR the signature can be forged using
# the known-hash shortcut in ECDSA verification
attacker_sig = forge_signature_for_known_hash(uint256(1))

# input_2 is now anyone-can-spend
```

**Why it works:** Bitcoin Core's `SignatureHash()` function returns `uint256(1)` when `SIGHASH_SINGLE` is used and `input_index >= len(outputs)`. This is a consensus rule that cannot be changed without a hard fork.

---

## 3. Witness UTXO Amount Lie (Trezor/Ledger Fee Attack, 2020)

**Related checkpoint:** 0x0006

**Vulnerability:** SegWit signing only requires the witness UTXO (value + scriptPubKey), not the full previous transaction. An attacker lies about the UTXO amount across two signing sessions, tricking the signer into paying excessive fees.

```
# True UTXO: 1.0 BTC at outpoint txid:0
true_utxo = { value: 1.0 BTC, scriptPubKey: P2WPKH(victim) }

# === Session 1: Attacker claims the UTXO is worth 1.5 BTC ===
psbt_1 = create_psbt()
psbt_1.add_input(outpoint=txid:0, witness_utxo={ value: 1.5 BTC, scriptPubKey: P2WPKH(victim) })
psbt_1.add_output(address=recipient, value=1.0 BTC)
# Displayed fee: 1.5 - 1.0 = 0.5 BTC (signer thinks this is the fee)
# Signer thinks: "0.5 BTC fee is high but I'll sign"
sig_1 = sign(psbt_1, input_index=0, key=victim)

# === Session 2: Attacker claims the UTXO is worth 2.0 BTC ===
psbt_2 = create_psbt()
psbt_2.add_input(outpoint=txid:0, witness_utxo={ value: 2.0 BTC, scriptPubKey: P2WPKH(victim) })
psbt_2.add_output(address=recipient, value=1.5 BTC)
# Displayed fee: 2.0 - 1.5 = 0.5 BTC (same apparent fee)
sig_2 = sign(psbt_2, input_index=0, key=victim)

# Attacker broadcasts psbt_1 (the one with 1.0 BTC output)
# Actual fee: 1.0 BTC (true value) - 1.0 BTC (output) = 0.0 BTC? No!
# Wait — true UTXO is 1.0 BTC and output is 1.0 BTC, so fee is 0.
# The attack works differently: the attacker uses the LOWER claimed value

# Correct attack flow:
# Session 1: claim 0.8 BTC, output 0.7 BTC → apparent fee 0.1 BTC
# Session 2: claim 0.9 BTC, output 0.8 BTC → apparent fee 0.1 BTC
# True value: 1.0 BTC
# Broadcast session 1: actual fee = 1.0 - 0.7 = 0.3 BTC (3x the displayed fee)
```

**Why it works:** The SegWit sighash algorithm commits to the witness UTXO amount provided in the PSBT, but the actual amount on-chain is determined by the real UTXO. The signer cannot distinguish a lied amount from the true amount without the full previous transaction.

---

## 4. Change Output Redirection (MITM Between Signers)

**Related checkpoint:** 0x0004

**Vulnerability:** In a 2-of-3 multisig PSBT workflow, a MITM coordinator modifies the change output address between collecting signatures from different signers.

```
# Legitimate PSBT constructed by Signer A
psbt_original = create_psbt()
psbt_original.add_input(utxo=multisig_utxo, value=5.0 BTC)
psbt_original.add_output(address=merchant, value=3.0 BTC)         # payment
psbt_original.add_output(address=multisig_change, value=1.9999 BTC)  # change

# Signer A reviews and signs with SIGHASH_ALL
sig_a = sign(psbt_original, input_index=0, key=signer_a)

# === MITM coordinator intercepts the PSBT ===
psbt_modified = psbt_original.clone()
psbt_modified.outputs[1].scriptPubKey = P2WSH(attacker_address)  # redirect change

# Signer A's SIGHASH_ALL signature is now INVALID on psbt_modified
# because SIGHASH_ALL commits to all outputs.
# BUT if the system uses SIGHASH_SINGLE on the payment output:

# Signer A signs with SIGHASH_SINGLE (commits only to output at same index)
sig_a = sign(psbt_original, input_index=0, sighash=SIGHASH_SINGLE, key=signer_a)
# This signature only commits to output[0] (merchant payment)
# Change output at index 1 is NOT committed

# Signer B receives the MODIFIED PSBT and signs (does not notice change swap)
sig_b = sign(psbt_modified, input_index=0, sighash=SIGHASH_ALL, key=signer_b)

# Coordinator has sig_a (SIGHASH_SINGLE, valid) + sig_b (on modified PSBT, valid)
# 2-of-3 threshold met → finalize and broadcast
# 1.9999 BTC change goes to attacker
```

**Why it works:** Mixed sighash types within a multisig create asymmetric commitment levels. If even one signer uses a weaker sighash, the uncommitted fields become attacker-controlled.

---

## 5. MuSig2 Nonce Reuse Key Extraction

**Related checkpoint:** 0x000c

**Vulnerability:** If a MuSig2 signer reuses the same nonce across two signing sessions, any co-signer can extract the victim's private key using simple algebra.

```
# MuSig2 Schnorr partial signature: s = r + e * x
#   r = secret nonce, e = challenge (hash of message + public data), x = private key

# === Session 1 ===
# Victim generates nonce k and computes public nonce R = k * G
R = k * G
# Challenge for session 1
e1 = hash(R_agg || pubkey_agg || message_1)
# Victim's partial signature
s1 = k + e1 * x    # (mod curve order n)

# === Session 2 (victim reuses nonce k!) ===
R = k * G           # SAME nonce!
# Challenge for session 2 (different message or different aggregate nonce)
e2 = hash(R_agg || pubkey_agg || message_2)
# Victim's partial signature
s2 = k + e2 * x    # (mod n)

# === Attacker extracts private key ===
# s1 - s2 = (k + e1*x) - (k + e2*x) = (e1 - e2) * x
# x = (s1 - s2) / (e1 - e2)  mod n
x = (s1 - s2) * inverse(e1 - e2, n) % n

# Attacker now has victim's private key x
# Total cost: one modular subtraction + one modular inverse
# No brute force, no computational hardness — pure algebra
```

**Why it works:** Schnorr signatures are linear in the nonce. Reusing the nonce across two different challenges creates a system of two equations in two unknowns (k and x). Subtracting eliminates k, leaving x directly solvable.

**Triggering nonce reuse:** A malicious co-signer aborts session 1 after receiving the victim's nonce commitment, then starts session 2. If the victim's implementation deterministically regenerates the same nonce (or caches/replays the old one), the attack succeeds.

---

## 6. BRC-20 Fee Sniping via PSBT Manipulation

**Related checkpoints:** 0x0008, 0x0009

**Vulnerability:** In BRC-20/Ordinals marketplaces, PSBTs for inscription trades are exchanged between buyers and sellers. An attacker monitors the exchange, constructs a competing transaction with a higher fee, and "snipes" the inscription transfer.

```
# Seller lists BRC-20 inscription for sale via PSBT
seller_psbt = create_psbt()
seller_psbt.add_input(utxo=inscription_utxo, value=0.00000546 BTC)  # dust with inscription
seller_psbt.add_output(address=seller, value=0.1 BTC)                # sale price
# Seller signs with SIGHASH_SINGLE|ANYONECANPAY
sig = sign(seller_psbt, input_0, sighash=SIGHASH_SINGLE|SIGHASH_ANYONECANPAY, key=seller)

# Seller publishes signed PSBT to marketplace (publicly visible)

# === Legitimate buyer ===
buyer_psbt = seller_psbt.clone()
buyer_psbt.add_input(utxo=buyer_utxo, value=0.2 BTC)               # buyer funding
buyer_psbt.add_output(address=buyer, value=0.00000546 BTC)          # inscription to buyer
buyer_psbt.add_output(address=buyer_change, value=0.0999 BTC)       # buyer change
buyer_sig = sign(buyer_psbt, input_1, key=buyer)
# fee = 0.2 + 0.00000546 - 0.1 - 0.00000546 - 0.0999 = ~0.0001 BTC

# === Snipping attacker (monitors mempool or marketplace) ===
snipe_psbt = seller_psbt.clone()  # reuses seller's valid SIGHASH_SINGLE|ANYONECANPAY sig
snipe_psbt.add_input(utxo=attacker_utxo, value=0.3 BTC)
snipe_psbt.add_output(address=attacker, value=0.00000546 BTC)       # inscription to attacker
snipe_psbt.add_output(address=seller, value=0.1 BTC)                # matches seller expectation
# fee = higher than buyer's fee → miners prefer this transaction
snipe_sig = sign(snipe_psbt, input_1, key=attacker)
broadcast(snipe_psbt)  # Attacker gets the inscription, seller gets paid

# Buyer's transaction is now invalid (seller's input already spent)
```

**Why it works:** `SIGHASH_SINGLE|SIGHASH_ANYONECANPAY` commits only to the seller's input and the output at the same index. Anyone can add inputs and additional outputs, creating a competing transaction. The highest-fee transaction wins in the mempool.

---

## 7. Taproot Output Key Tweak Poisoning

**Related checkpoint:** 0x000b

**Vulnerability:** A malicious coordinator constructs a Taproot output where the internal key and tweak are manipulated so that the output key is actually controlled by the attacker, even though the Tapscript tree appears to contain a legitimate multisig.

```
# Legitimate setup: 2-of-2 MuSig2 with a Tapscript fallback
# P_agg = aggregate public key of (Alice, Bob)
# Tapscript tree has one leaf: OP_CHECKSIG with Alice's key (timeout recovery)

# Honest construction:
merkle_root = tagged_hash("TapLeaf", leaf_version || script_size || recovery_script)
tweak = tagged_hash("TapTweak", P_agg || merkle_root)
Q = P_agg + tweak * G   # output key

# === Attacker (malicious coordinator) ===
# Attacker wants Q to equal their own key Q_attacker
# They compute: fake_P = Q_attacker - tweak' * G
# where tweak' = tagged_hash("TapTweak", fake_P || fake_merkle_root)

# The attacker iterates to find consistent (fake_P, fake_merkle_root):
# 1. Choose a fake_merkle_root (e.g., hash of OP_TRUE script)
# 2. Compute tweak' = tagged_hash("TapTweak", Q_attacker_internal || fake_merkle_root)
# 3. Compute Q = Q_attacker_internal + tweak' * G
# 4. This Q is now the output key — attacker knows the private key for key-path spend

# Attacker tells Alice and Bob:
# "The internal key is fake_P and the merkle root is fake_merkle_root"
# Alice and Bob cannot spend via key path (they don't know fake_P's private key)
# The Tapscript tree contains OP_TRUE — attacker can spend via script path

# OR simpler: attacker uses their own key as internal key
Q_attacker = attacker_privkey * G
merkle_root = tagged_hash("TapLeaf", leaf_version || script_size || legitimate_script)
tweak = tagged_hash("TapTweak", Q_attacker || merkle_root)
output_key = Q_attacker + tweak * G
# Attacker can spend via key path at any time — no script conditions needed
# Other parties believe the output requires script-path multisig
```

**Why it works:** The key path is always available if you know the internal key's private key. A malicious coordinator who controls the internal key can bypass any Tapscript conditions, since key-path spending does not reveal or check the script tree.

---

## 8. Premature Finalization with Partial Signatures

**Related checkpoint:** 0x000f

**Vulnerability:** A finalizer constructs the witness without validating that all required signatures are present and valid. The resulting transaction may fail on-chain, waste fees, or in edge cases satisfy a weaker spending condition than intended.

```
# 2-of-3 multisig P2WSH PSBT
required_sigs = 2
psbt.add_input(utxo=multisig_utxo, witness_script=multisig_2of3_script)

# Only 1 signature collected (from Signer A)
psbt.partial_sigs = { pubkey_a: sig_a }

# === Faulty finalizer does not check signature count ===
def faulty_finalize(psbt, input_index):
    sigs = psbt.get_partial_sigs(input_index)
    # BUG: no check for len(sigs) >= required_sigs
    witness = []
    witness.append(b'')               # OP_0 for CHECKMULTISIG bug
    for sig in sigs.values():
        witness.append(sig)
    # Missing second signature — pads with empty bytes
    while len(witness) < required_sigs + 1:
        witness.append(b'')           # empty placeholder
    witness.append(psbt.witness_script)
    return witness

# Resulting witness: [OP_0, sig_a, '', witness_script]
# This will fail OP_CHECKMULTISIG (needs 2 valid sigs, got 1)
# Transaction is broadcast and REJECTED — fees are wasted if miner attempts it

# Worse case: if the witness script has an alternative path
# e.g., OP_IF <2> <A> <B> <C> <3> OP_CHECKMULTISIG OP_ELSE <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <A> OP_CHECKSIG OP_ENDIF
# A faulty finalizer might accidentally satisfy the ELSE branch
# if nLockTime is past the timeout — unintended single-sig spend
```

**Why it works:** PSBT finalization is a data transformation step that constructs the witness. If it does not validate the cryptographic correctness of the signatures and the completeness of the required set, it may produce an invalid or unintended witness structure.
