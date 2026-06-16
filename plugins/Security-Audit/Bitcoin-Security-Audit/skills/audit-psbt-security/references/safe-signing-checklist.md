# PSBT Safe Signing Checklist

Pre-signing validation checklist for Bitcoin PSBT construction, signing, and finalization. Each section contains verification steps that should be completed before a signer produces a signature.

---

## 1. PSBT Structure Validation

- [ ] Verify PSBT magic bytes (`0x70736274FF`) are present and correct
- [ ] Verify PSBT version (v0 per BIP-174 or v2 per BIP-370) and that the parser supports the version
- [ ] Verify no duplicate keys exist within any key-value map (global, per-input, per-output)
- [ ] Verify all required global fields are present for the PSBT version
- [ ] Verify key-value pair lengths are within reasonable bounds (no oversized fields)
- [ ] Verify the unsigned transaction (v0) or transaction fields (v2) are well-formed
- [ ] Verify input and output counts are consistent between the global unsigned transaction and the per-input/per-output maps

---

## 2. Input Verification

- [ ] Verify the complete set of inputs matches what the signer expects (no injected inputs)
- [ ] For each non-witness input: verify `SHA256d(non_witness_utxo) == prevout.hash`
- [ ] For each non-witness input: verify the output index (`prevout.n`) is within bounds of the previous transaction
- [ ] For each witness input: verify the witness UTXO amount against the full previous transaction (if available) or an independent UTXO source
- [ ] Verify the scriptPubKey type matches the expected signing algorithm (ECDSA for legacy/SegWit, Schnorr for Taproot)
- [ ] Verify the derivation path (BIP-32) is consistent with the script type (44' for P2PKH, 49' for P2SH-P2WPKH, 84' for P2WPKH, 86' for P2TR)
- [ ] For P2SH inputs: verify `HASH160(redeemScript) == scriptPubKey script hash`
- [ ] For P2WSH inputs: verify `SHA256(witnessScript) == witness program`
- [ ] For Taproot inputs: verify `PSBT_IN_TAP_INTERNAL_KEY` matches the expected key
- [ ] For Taproot inputs: verify `PSBT_IN_TAP_MERKLE_ROOT` corresponds to the expected Tapscript tree
- [ ] Verify no input has been spent (double-spend check against known UTXO set if available)

---

## 3. Output Verification

- [ ] Verify the complete set of outputs matches what the signer expects (no added/removed/reordered outputs)
- [ ] Verify payment output addresses and amounts match the intended transaction
- [ ] Verify change output addresses belong to the signer's own wallet (check derivation path)
- [ ] Verify change amount equals `sum(input_values) - sum(payment_values) - fee`
- [ ] For Taproot outputs: verify the output key tweak is correctly computed from the internal key and merkle root
- [ ] Verify no outputs send to unspendable addresses (unless intentional, e.g., OP_RETURN)
- [ ] Verify output values are above dust threshold (546 satoshis for standard outputs) unless intentional (Ordinals)

---

## 4. Sighash and Fee Validation

- [ ] Verify the sighash type for each input matches the protocol's intended commitment level
- [ ] Reject `SIGHASH_NONE` unless explicitly allowlisted with documented justification
- [ ] For `SIGHASH_SINGLE`: verify `input_index < len(outputs)` (prevent the uint256(1) bug)
- [ ] For `SIGHASH_ANYONECANPAY` combinations: verify the intended modification rights are documented and correct
- [ ] Verify the sighash flag cannot be modified by an intermediary after the signer has approved it
- [ ] Compute and display the transaction fee: `fee = sum(input_values) - sum(output_values)`
- [ ] Verify fee is within acceptable bounds (absolute maximum, fee rate in sat/vB, percentage of transaction value)
- [ ] Verify fee rate calculation uses correct virtual size (vbytes) accounting for SegWit witness discount
- [ ] Check `nSequence` values: verify RBF signaling (`nSequence < 0xFFFFFFFE`) is intentional or disabled as appropriate

---

## 5. Multi-Party Protocol

- [ ] Verify the signer is participating in the expected signing session (check session ID)
- [ ] For MuSig2: verify nonce is freshly generated using a CSPRNG (not deterministic from the message)
- [ ] For MuSig2: verify the nonce has not been used in any previous session
- [ ] For MuSig2: verify all co-signer public nonces are received and committed before revealing own nonce
- [ ] For MuSig2: verify key aggregation uses correct BIP-327 coefficients (rogue-key protection)
- [ ] For multisig: verify the signing threshold (M-of-N) matches the expected configuration
- [ ] Verify that the PSBT has not been modified between signing rounds (compare global hash or output set)
- [ ] Verify communication channels between signers are authenticated and encrypted
- [ ] For PSBT combining: verify the combined PSBT only adds signatures, not new inputs or outputs

---

## 6. Timelock and Sequence

- [ ] Verify `nLockTime` is set correctly for the protocol's requirements (block height or Unix timestamp)
- [ ] Verify `nSequence` enables `nLockTime` enforcement (must be `< 0xFFFFFFFF` for at least one input)
- [ ] For relative timelocks (BIP-68): verify `nSequence` encodes the correct relative locktime
- [ ] Verify timelock values are within reasonable bounds (not set to far-future values that could lock funds permanently)
- [ ] For time-sensitive protocols (e.g., HTLCs, staking): verify the timelock window is sufficient for all parties to act
- [ ] Verify that OP_CHECKLOCKTIMEVERIFY and OP_CHECKSEQUENCEVERIFY in scripts are consistent with transaction-level timelocks

---

## 7. Post-Signing and Finalization

- [ ] Verify the signature is valid against the computed sighash before passing the PSBT to the next signer or finalizer
- [ ] For multisig: verify all required M-of-N signatures are present and valid before finalization
- [ ] For MuSig2: validate all partial signatures using `PartialSigVerify` before aggregation
- [ ] Verify the finalizer constructs the correct witness structure for the script type
- [ ] Verify the finalizer strips PSBT metadata (partial sigs, derivation paths, xpubs) from the final transaction
- [ ] Verify the finalized transaction serializes correctly and passes `testmempoolaccept` (or equivalent) before broadcast
- [ ] Never broadcast a partially signed transaction—complete all signing rounds first
- [ ] Destroy nonce material and session state after signing completes (or fails)

---

## 8. Operational Security

- [ ] Use hardware wallets or HSMs for key material storage—never expose private keys to general-purpose computers
- [ ] Display the full transaction summary (inputs, outputs, fee, sighash types) on the signing device before requesting confirmation
- [ ] Log all signing events with sufficient detail for forensic analysis (without logging key material)
- [ ] Implement rate limiting on signing requests to detect automated theft attempts
- [ ] Use air-gapped signing for high-value transactions (transfer PSBTs via QR code or SD card)
- [ ] Verify the PSBT source (check digital signatures or MACs on the PSBT payload if the protocol supports it)
- [ ] Monitor for unusual patterns: repeated signing requests, changing output addresses, escalating fees
