# Sighash Types Reference

Complete reference for Bitcoin sighash types, their commitment properties, security implications, and auditor decision guidance. Covers both legacy/SegWit (BIP-143) and Taproot (BIP-341) sighash behavior.

---

## 1. Sighash Flag Definitions

| Flag Name | Byte Value | Description |
|-----------|-----------|-------------|
| `SIGHASH_ALL` | `0x01` | Commits to all inputs and all outputs. Default for most transactions. |
| `SIGHASH_NONE` | `0x02` | Commits to all inputs but no outputs. Outputs can be freely modified. |
| `SIGHASH_SINGLE` | `0x03` | Commits to all inputs and only the output at the same index as the signed input. |
| `SIGHASH_ALL\|ANYONECANPAY` | `0x81` | Commits to only the signed input and all outputs. Other inputs can be added. |
| `SIGHASH_NONE\|ANYONECANPAY` | `0x82` | Commits to only the signed input and no outputs. Maximum modification freedom. |
| `SIGHASH_SINGLE\|ANYONECANPAY` | `0x83` | Commits to only the signed input and the output at the same index. |

### Taproot-Specific (BIP-341)

| Flag Name | Byte Value | Description |
|-----------|-----------|-------------|
| `SIGHASH_DEFAULT` | `0x00` | Taproot only. Equivalent to `SIGHASH_ALL` but uses a 64-byte signature (no sighash byte suffix). |

**Note:** In Taproot, `SIGHASH_DEFAULT` (`0x00`) produces the same commitment as `SIGHASH_ALL` (`0x01`) but the signature is 64 bytes instead of 65 bytes (the sighash byte is omitted). All other sighash types produce 65-byte signatures with the sighash byte appended.

---

## 2. Taproot Sighash Details (BIP-341)

Taproot sighash computation differs from legacy/SegWit in several important ways:

**Epoch byte:** Taproot sighash messages are prefixed with epoch `0x00` to prevent cross-version signature replay.

**Committed data for `SIGHASH_ALL` / `SIGHASH_DEFAULT`:**
- Transaction version (`nVersion`)
- Locktime (`nLockTime`)
- Hash of all input prevouts (txid + vout)
- Hash of all input amounts (all inputs, not just the signed one)
- Hash of all input scriptPubKeys
- Hash of all input `nSequence` values
- Hash of all outputs (scriptPubKey + value)
- Spend type (key path vs script path)
- Input index being signed

**Key difference from SegWit:** Taproot commits to ALL input amounts and ALL input scriptPubKeys, not just the one being signed. This prevents the fee overpayment attack at the sighash level (though UTXO amount verification is still recommended at the application level).

**Annex:** If the input has an annex (witness stack element starting with `0x50`), its hash is included in the sighash. The annex is reserved for future protocol extensions.

**Script path additions:** When signing via script path, the sighash additionally commits to:
- Tapleaf hash (leaf version + script)
- Key version (`0x00` currently)
- Code separator position (`OP_CODESEPARATOR` index, or `0xFFFFFFFF` if none)

---

## 3. Commitment Matrix

What each sighash type commits to (and what can be modified by others):

| Sighash Type | Own Input | Other Inputs | All Outputs | Matched Output | Input Amounts (Taproot) |
|-------------|-----------|-------------|-------------|---------------|------------------------|
| `ALL` | Yes | Yes | Yes | N/A | Yes (Taproot only) |
| `NONE` | Yes | Yes | **No** | **No** | Yes (Taproot only) |
| `SINGLE` | Yes | Yes | **No** | Yes | Yes (Taproot only) |
| `ALL\|ANYONECANPAY` | Yes | **No** | Yes | N/A | **No** |
| `NONE\|ANYONECANPAY` | Yes | **No** | **No** | **No** | **No** |
| `SINGLE\|ANYONECANPAY` | Yes | **No** | **No** | Yes | **No** |

**"Own Input" always includes:** prevout (txid:vout), scriptPubKey, sequence, and amount (for SegWit/Taproot).

**"Other Inputs":** When committed, the signature is invalidated if any other input is added, removed, or modified. When not committed (`ANYONECANPAY`), additional inputs can be freely added.

**"All Outputs":** When committed, no outputs can be added, removed, or modified. When not committed, outputs are freely modifiable (except the matched output for `SIGHASH_SINGLE`).

---

## 4. Security Implications Matrix

| Sighash Type | Who Can Modify What | Primary Attack Vector | Risk Level |
|-------------|--------------------|-----------------------|------------|
| `ALL` | Nobody (fully committed) | None from sighash misuse | Low |
| `NONE` | Anyone can replace ALL outputs | Output theft — redirect all funds | **Critical** |
| `SINGLE` | Anyone can modify non-matched outputs | Steal change outputs; index overflow → anyone-can-spend | **High** |
| `ALL\|ANYONECANPAY` | Anyone can add inputs | Input injection — coerce spending of additional UTXOs | Medium |
| `NONE\|ANYONECANPAY` | Anyone can add inputs AND replace all outputs | Total transaction hijack — maximum attack surface | **Critical** |
| `SINGLE\|ANYONECANPAY` | Anyone can add inputs and modify non-matched outputs | Combined input injection + change theft + index overflow | **Critical** |

### Legitimate Use Cases

| Sighash Type | Legitimate Use Case |
|-------------|-------------------|
| `ALL` | Standard transactions, most use cases |
| `NONE` | Extremely rare. Possibly a "blank check" in a specific multi-step protocol where the signer intentionally defers output selection to a trusted party |
| `SINGLE` | Colored coins, marketplace orders where signer commits to receiving a specific output but allows other outputs to be arranged by counterparty |
| `ALL\|ANYONECANPAY` | Crowdfunding / pledge transactions — "I pledge this input if the total reaches the goal" |
| `NONE\|ANYONECANPAY` | Almost never legitimate. Theoretically used in exotic multi-party protocols |
| `SINGLE\|ANYONECANPAY` | Marketplace listings — seller commits to receiving payment (matched output) and spending their specific UTXO, buyer adds funding inputs and additional outputs |

---

## 5. SIGHASH_SINGLE Index Bug Deep Dive

### The Bug

When `SIGHASH_SINGLE` is applied to input at index `i` and `i >= len(tx.outputs)`, Bitcoin's `SignatureHash()` function returns `uint256(1)` instead of computing a real sighash.

### Why It Exists

```
// Bitcoin Core SignatureHash() (simplified)
if (nHashType == SIGHASH_SINGLE) {
    if (nIn >= txTo.vout.size()) {
        // Historical behavior: return 1
        // This is consensus-critical and cannot be changed
        return uint256(1);
    }
}
```

This was originally an unintended edge case that became a consensus rule. Changing it would require a hard fork.

### Impact

- The sighash `uint256(1)` is a known constant
- Any party can produce a valid ECDSA signature for a known hash value
- This effectively makes the input anyone-can-spend

### Exploitation Requirements

1. Transaction has more inputs than outputs
2. At least one input at index `>= len(outputs)` is signed with `SIGHASH_SINGLE`
3. The attacker recognizes the condition and computes a signature for `uint256(1)`

### Mitigation

```
# Before signing with SIGHASH_SINGLE, ALWAYS verify:
assert input_index < len(tx.outputs), "SIGHASH_SINGLE requires matching output"
```

### Taproot Behavior

**BIP-341 fixes this bug for Taproot inputs.** If `SIGHASH_SINGLE` is used and the input index exceeds the output count, the signing operation fails (returns error) rather than returning a known hash. This fix only applies to Taproot (v1 witness) inputs — legacy and SegWit v0 inputs retain the original consensus behavior.

---

## 6. Taproot vs Legacy Sighash Differences

| Property | Legacy (pre-SegWit) | SegWit v0 (BIP-143) | Taproot (BIP-341) |
|----------|--------------------|--------------------|-------------------|
| Hash algorithm | SHA256d of serialized tx | SHA256d of BIP-143 components | Tagged hash (`TapSighash`) |
| Input amount committed | No | Yes (own input only) | Yes (ALL inputs) |
| Input scriptPubKey committed | No | No | Yes (ALL inputs) |
| SIGHASH_SINGLE index bug | Returns uint256(1) | Returns uint256(1) | Returns error (fixed) |
| Signature scheme | ECDSA (DER-encoded) | ECDSA (DER-encoded) | Schnorr (BIP-340, 64 bytes) |
| SIGHASH_DEFAULT | N/A | N/A | `0x00` = ALL with 64-byte sig |
| Annex support | No | No | Yes (witness annex) |
| Script path commitment | N/A | N/A | Tapleaf hash + code separator |
| Quadratic hashing | Possible | Fixed (BIP-143) | Fixed |

### Key Security Implications

1. **All-input-amount commitment (Taproot):** The Trezor/Ledger fee overpayment attack is mitigated at the sighash level for Taproot inputs because the signature commits to all input amounts. However, the witness UTXO amounts must still be verified because the signer commits to the *claimed* amounts — if all amounts are lied about consistently, the fee can still be manipulated.

2. **All-input-scriptPubKey commitment (Taproot):** Prevents attacks where an input's script type is changed between signing sessions (e.g., changing a P2TR input to appear as P2WPKH).

3. **SIGHASH_SINGLE fix (Taproot):** Eliminates the anyone-can-spend condition for Taproot inputs. Legacy and SegWit v0 inputs remain vulnerable.

4. **Schnorr signatures:** Enable MuSig2 and other multi-signature schemes due to key and signature linearity. However, this linearity also makes nonce reuse catastrophic (see checkpoint 0x000c).

---

## 7. Auditor Decision Guide

Use this flowchart when auditing sighash usage in a Bitcoin protocol:

```
What sighash type is used?
│
├── SIGHASH_ALL (0x01) or SIGHASH_DEFAULT (0x00, Taproot)
│   └── LOW RISK — Standard commitment. Verify no downgrade paths exist.
│
├── SIGHASH_NONE (0x02)
│   └── CRITICAL — Ask: Is there a documented, justified reason?
│       ├── No  → FLAG as critical vulnerability
│       └── Yes → Verify the justification. Check if SIGHASH_ALL would work instead.
│
├── SIGHASH_SINGLE (0x03)
│   └── HIGH RISK — Verify:
│       ├── 1. input_index < len(outputs) (ALWAYS — prevents uint256(1) bug)
│       ├── 2. Non-matched outputs cannot be stolen (change output safety)
│       └── 3. Is this a marketplace/order pattern? Verify output commitment is sufficient.
│
├── ANY|ANYONECANPAY (0x81, 0x82, 0x83)
│   └── Verify:
│       ├── 1. Is input injection acceptable in this context?
│       ├── 2. Can the signer's other UTXOs be coerced into the transaction?
│       └── 3. Check the combined modification rights:
│           ├── 0x81 (ALL|ACP): Only input injection — MEDIUM RISK
│           ├── 0x82 (NONE|ACP): Total hijack possible — CRITICAL
│           └── 0x83 (SINGLE|ACP): Input injection + change theft — CRITICAL
│
└── Unknown or dynamic sighash selection
    └── FLAG — Sighash must be statically determined per transaction type.
        Verify no user/server input controls the sighash flag.
```

### Quick Reference Questions for Auditors

1. **Can the sighash flag be influenced by untrusted input?** (e.g., API parameter, PSBT field from counterparty) → If yes, flag as vulnerability.

2. **Does every SIGHASH_SINGLE usage have a matching output?** → If not guaranteed, flag the uint256(1) bug risk.

3. **Is SIGHASH_NONE used anywhere?** → If yes, require explicit documented justification. Default to flagging as critical.

4. **For ANYONECANPAY: can the signer's other UTXOs be injected?** → If the protocol doesn't protect against input injection, flag as vulnerability.

5. **For Taproot: is the code using SIGHASH_DEFAULT correctly?** → Verify 64-byte vs 65-byte signature handling is consistent.

6. **Are legacy and Taproot inputs mixed in the same transaction?** → Verify sighash computation is correct for each input type (ECDSA vs Schnorr, different commitment properties).

7. **Is the fee overpayment attack mitigated?** → For SegWit v0: require full previous transaction. For Taproot: verify all input amounts are committed but still validate against independent source.
