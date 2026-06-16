# TypeScript Vulnerable Patterns for PSBT Audits

Real-world vulnerable TypeScript patterns using `bitcoinjs-lib`, `@scure/btc-signer`, `bip174`, `tiny-secp256k1`, `ecpair`, and `@noble/secp256k1`. Each section maps to a checkpoint in the PSBT audit skill.

---

## 0x0000 — SIGHASH_NONE allows output theft

### Vulnerable: Wallet uses SIGHASH_NONE in listing builder

```typescript
// VULNERABLE — seller signs with SIGHASH_NONE, outputs can be replaced
import * as bitcoin from "bitcoinjs-lib";
import ECPairFactory from "ecpair";
import * as ecc from "tiny-secp256k1";

const ECPair = ECPairFactory(ecc);

async function createSellerListing(
  sellerUtxo: UTXO,
  sellerKeyPair: ReturnType<typeof ECPair.fromWIF>,
  priceInSats: number
) {
  const psbt = new bitcoin.Psbt({ network: bitcoin.networks.bitcoin });

  psbt.addInput({
    hash: sellerUtxo.txid,
    index: sellerUtxo.vout,
    witnessUtxo: {
      script: Buffer.from(sellerUtxo.scriptPubKey, "hex"),
      value: sellerUtxo.value,
    },
    sighashType: bitcoin.Transaction.SIGHASH_NONE, // CRITICAL: commits to zero outputs
  });

  psbt.addOutput({
    address: sellerAddress,
    value: priceInSats,
  });

  // Seller signs — this signature is valid with ANY outputs
  psbt.signInput(0, sellerKeyPair, [bitcoin.Transaction.SIGHASH_NONE]);

  // Attacker receives this PSBT, strips outputs, redirects all funds
  return psbt.toBase64();
}
```

### Secure: Always use SIGHASH_ALL or SIGHASH_SINGLE|ANYONECANPAY for listings

```typescript
async function secureSellerListing(sellerUtxo: UTXO, sellerKeyPair: any, priceInSats: number) {
  const psbt = new bitcoin.Psbt({ network: bitcoin.networks.bitcoin });

  // For marketplace listings: SIGHASH_SINGLE|ANYONECANPAY
  // Commits to: own input + output at same index (the payment output)
  const SIGHASH_SINGLE_ACP =
    bitcoin.Transaction.SIGHASH_SINGLE | bitcoin.Transaction.SIGHASH_ANYONECANPAY;

  psbt.addInput({
    hash: sellerUtxo.txid,
    index: sellerUtxo.vout,
    witnessUtxo: { script: Buffer.from(sellerUtxo.scriptPubKey, "hex"), value: sellerUtxo.value },
    sighashType: SIGHASH_SINGLE_ACP,
  });

  psbt.addOutput({ address: sellerAddress, value: priceInSats });
  psbt.signInput(0, sellerKeyPair, [SIGHASH_SINGLE_ACP]);
  return psbt.toBase64();
}
```

---

## 0x0001 — SIGHASH_SINGLE index overflow (uint256(1) bug)

### Vulnerable: Batch signing without index parity check

```typescript
// VULNERABLE — inputs exceed outputs, SIGHASH_SINGLE on high-index input
import * as bitcoin from "bitcoinjs-lib";

function batchSignInputs(psbt: bitcoin.Psbt, keyPair: any) {
  // Transaction: 5 inputs, 3 outputs
  for (let i = 0; i < psbt.inputCount; i++) {
    // SIGHASH_SINGLE on input[3] and input[4] when only 3 outputs exist
    // input_index >= len(outputs) → sighash returns uint256(1)
    // These inputs become anyone-can-spend
    psbt.signInput(i, keyPair, [bitcoin.Transaction.SIGHASH_SINGLE]);
  }
  return psbt;
}
```

### Secure: Validate index parity before signing

```typescript
function safeBatchSign(psbt: bitcoin.Psbt, keyPair: any) {
  const outputCount = psbt.txOutputs.length;

  for (let i = 0; i < psbt.inputCount; i++) {
    const sighashType = psbt.data.inputs[i].sighashType ?? bitcoin.Transaction.SIGHASH_ALL;
    const baseType = sighashType & 0x1f; // strip ANYONECANPAY flag

    if (baseType === bitcoin.Transaction.SIGHASH_SINGLE && i >= outputCount) {
      throw new Error(
        `SIGHASH_SINGLE on input[${i}] but only ${outputCount} outputs — ` +
          `would produce uint256(1) anyone-can-spend sighash`
      );
    }
    psbt.signInput(i, keyPair, [sighashType]);
  }
}
```

---

## 0x0002 — ANYONECANPAY|NONE total transaction hijack

### Vulnerable: Crowdfund uses wrong ANYONECANPAY combination

```typescript
// VULNERABLE — uses ANYONECANPAY|NONE instead of ANYONECANPAY|ALL
import * as bitcoin from "bitcoinjs-lib";

function createPledgeInput(pledgerUtxo: UTXO, pledgerKeyPair: any) {
  const psbt = new bitcoin.Psbt({ network: bitcoin.networks.bitcoin });

  psbt.addInput({
    hash: pledgerUtxo.txid,
    index: pledgerUtxo.vout,
    witnessUtxo: {
      script: Buffer.from(pledgerUtxo.scriptPubKey, "hex"),
      value: pledgerUtxo.value,
    },
    // 0x82 = ANYONECANPAY | NONE — commits to NOTHING except own input
    // Anyone can replace ALL outputs AND add more inputs
    sighashType: 0x82,
  });

  // Intended: pledge to a crowdfund goal address
  psbt.addOutput({ address: crowdfundAddress, value: pledgerUtxo.value - 500 });

  psbt.signInput(0, pledgerKeyPair, [0x82]);
  return psbt.toBase64();

  // Attacker reuses the signed input, strips all outputs,
  // adds output to their own address — signature still valid
}
```

### Secure: Use ANYONECANPAY|ALL for crowdfund pledges

```typescript
function securePledge(pledgerUtxo: UTXO, pledgerKeyPair: any) {
  const psbt = new bitcoin.Psbt({ network: bitcoin.networks.bitcoin });
  // 0x81 = ANYONECANPAY | ALL — allows adding inputs but locks ALL outputs
  const SIGHASH_ALL_ACP = 0x81;

  psbt.addInput({
    hash: pledgerUtxo.txid,
    index: pledgerUtxo.vout,
    witnessUtxo: { /* ... */ },
    sighashType: SIGHASH_ALL_ACP,
  });
  psbt.addOutput({ address: crowdfundAddress, value: pledgerUtxo.value - 500 });
  psbt.signInput(0, pledgerKeyPair, [SIGHASH_ALL_ACP]);
  return psbt.toBase64();
}
```

---

## 0x0003 — Input injection between signing rounds

### Vulnerable: Coordinator adds inputs after participant review

```typescript
// VULNERABLE — coordinator can inject inputs between signing rounds
import * as bitcoin from "bitcoinjs-lib";

class PSBTCoordinator {
  private psbt: bitcoin.Psbt;

  constructor() {
    this.psbt = new bitcoin.Psbt({ network: bitcoin.networks.bitcoin });
  }

  addParticipantInput(utxo: UTXO) {
    this.psbt.addInput({
      hash: utxo.txid,
      index: utxo.vout,
      witnessUtxo: { script: Buffer.from(utxo.scriptPubKey, "hex"), value: utxo.value },
    });
  }

  // Participant signs — only inspects their own input
  async collectSignature(inputIndex: number, signerKeyPair: any) {
    // BUG: participant doesn't verify the full input set
    // Coordinator could have added victim's other UTXOs as additional inputs
    this.psbt.signInput(inputIndex, signerKeyPair);
  }

  // After participant signs, coordinator adds more inputs!
  injectInput(victimUtxo: UTXO) {
    // This invalidates SIGHASH_ALL signatures but NOT SIGHASH_ANYONECANPAY
    this.psbt.addInput({
      hash: victimUtxo.txid,
      index: victimUtxo.vout,
      witnessUtxo: { script: Buffer.from(victimUtxo.scriptPubKey, "hex"), value: victimUtxo.value },
    });
  }
}
```

### Secure: Freeze input set and verify before signing

```typescript
class SecurePSBTCoordinator {
  async collectSignature(psbt: bitcoin.Psbt, inputIndex: number, signerKeyPair: any) {
    // Hash the full input set before signing
    const inputSetHash = crypto
      .createHash("sha256")
      .update(
        psbt.data.inputs
          .map((_, i) => {
            const txInput = psbt.txInputs[i];
            return `${Buffer.from(txInput.hash).reverse().toString("hex")}:${txInput.index}`;
          })
          .join(",")
      )
      .digest("hex");

    // Display ALL inputs to the signer for approval
    console.log(`Signing input ${inputIndex} of ${psbt.inputCount} total inputs`);
    console.log(`Input set hash: ${inputSetHash}`);
    console.log(`Total input value: ${psbt.data.inputs.reduce((s, i) => s + (i.witnessUtxo?.value ?? 0), 0)}`);

    // Signer verifies the full set before signing
    psbt.signInput(inputIndex, signerKeyPair);
  }
}
```

---

## 0x0004 — Output mutation after first signature

### Vulnerable: Change address swapped between signing rounds

```typescript
// VULNERABLE — outputs modifiable between signing rounds in multisig
import * as bitcoin from "bitcoinjs-lib";

async function multisigSigningFlow(
  psbt: bitcoin.Psbt,
  signer1: any,
  signer2: any
) {
  // Signer 1 reviews outputs and signs
  psbt.signInput(0, signer1);

  // --- MITM window: coordinator can modify the PSBT here ---
  // If signer1 used SIGHASH_SINGLE, change output is NOT committed

  // Coordinator replaces change output address
  // bitcoinjs-lib Psbt doesn't expose direct output modification,
  // but raw PSBT manipulation via psbt.data is possible:
  const outputData = psbt.data.globalMap.unsignedTx as any;
  // Swap change address in the raw transaction
  // signer1's SIGHASH_SINGLE signature remains valid (only commits to output[0])

  // Signer 2 reviews the MODIFIED PSBT and signs
  psbt.signInput(0, signer2);
  // 2-of-3 threshold met — change goes to attacker
}
```

### Secure: Lock outputs before any signing

```typescript
function verifyOutputIntegrity(psbt: bitcoin.Psbt, expectedOutputsHash: string) {
  const currentHash = crypto
    .createHash("sha256")
    .update(
      psbt.txOutputs
        .map((o) => `${o.address}:${o.value}`)
        .join("|")
    )
    .digest("hex");

  if (currentHash !== expectedOutputsHash) {
    throw new Error("Output set has been modified since initial review — aborting signing");
  }
}
```

---

## 0x0005 — Non-witness UTXO hash not verified

### Vulnerable: Legacy input signed without prevout hash check

```typescript
// VULNERABLE — accepts non-witness UTXO without hash verification
import * as bitcoin from "bitcoinjs-lib";

function signLegacyInput(psbt: bitcoin.Psbt, inputIndex: number, keyPair: any) {
  const input = psbt.data.inputs[inputIndex];

  if (input.nonWitnessUtxo) {
    // BUG: no verification that SHA256d(nonWitnessUtxo) matches prevout hash
    // An attacker can supply a fake previous TX with inflated output value
    const prevTx = bitcoin.Transaction.fromBuffer(input.nonWitnessUtxo);
    const claimedValue = prevTx.outs[psbt.txInputs[inputIndex].index].value;
    console.log(`Input value: ${claimedValue} sats`); // could be fake!
  }

  // Signs without verifying the UTXO is genuine
  psbt.signInput(inputIndex, keyPair);
}
```

### Secure: Verify prevout hash before signing

```typescript
function verifiedSignLegacyInput(psbt: bitcoin.Psbt, inputIndex: number, keyPair: any) {
  const input = psbt.data.inputs[inputIndex];
  const txInput = psbt.txInputs[inputIndex];

  if (input.nonWitnessUtxo) {
    const prevTx = bitcoin.Transaction.fromBuffer(input.nonWitnessUtxo);
    const computedTxid = prevTx.getId();
    const expectedTxid = Buffer.from(txInput.hash).reverse().toString("hex");

    if (computedTxid !== expectedTxid) {
      throw new Error(
        `Non-witness UTXO hash mismatch: computed ${computedTxid}, expected ${expectedTxid}. ` +
          `Possible fee manipulation attack.`
      );
    }

    // Also verify output index is in bounds
    if (txInput.index >= prevTx.outs.length) {
      throw new Error(`Output index ${txInput.index} out of bounds (tx has ${prevTx.outs.length} outputs)`);
    }
  }

  psbt.signInput(inputIndex, keyPair);
}
```

---

## 0x0006 — Witness UTXO amount lie (fee overpayment)

### Vulnerable: SegWit signing trusts witness UTXO amount without verification

```typescript
// VULNERABLE — witness UTXO amount accepted without cross-check
import * as bitcoin from "bitcoinjs-lib";

async function signSegwitInput(
  psbt: bitcoin.Psbt,
  inputIndex: number,
  keyPair: any
) {
  const input = psbt.data.inputs[inputIndex];

  // Only checks witness UTXO is present — not that the amount is correct
  if (!input.witnessUtxo) {
    throw new Error("Missing witness UTXO");
  }

  // Fee calculation uses the CLAIMED amount (could be a lie)
  const totalIn = psbt.data.inputs.reduce(
    (sum, inp) => sum + (inp.witnessUtxo?.value ?? 0),
    0
  );
  const totalOut = psbt.txOutputs.reduce((sum, out) => sum + out.value, 0);
  const fee = totalIn - totalOut;
  console.log(`Fee: ${fee} sats (${(fee / psbt.extractTransaction().virtualSize()).toFixed(1)} sat/vB)`);
  // This fee display could be WRONG if witness UTXO amounts are inflated

  psbt.signInput(inputIndex, keyPair);
}
```

### Secure: Cross-reference with full previous transaction or UTXO lookup

```typescript
import { fetchTransaction } from "./bitcoin-rpc";

async function verifiedSignSegwit(
  psbt: bitcoin.Psbt,
  inputIndex: number,
  keyPair: any
) {
  const input = psbt.data.inputs[inputIndex];
  const txInput = psbt.txInputs[inputIndex];

  if (!input.witnessUtxo) throw new Error("Missing witness UTXO");

  // Fetch the full previous transaction to verify the claimed amount
  const prevTxHex = await fetchTransaction(
    Buffer.from(txInput.hash).reverse().toString("hex")
  );
  const prevTx = bitcoin.Transaction.fromHex(prevTxHex);
  const realValue = prevTx.outs[txInput.index].value;

  if (input.witnessUtxo.value !== realValue) {
    throw new Error(
      `Witness UTXO amount mismatch! Claimed: ${input.witnessUtxo.value}, ` +
        `actual: ${realValue}. Possible fee overpayment attack (CVE-2020-14199).`
    );
  }

  // Also enforce fee bounds
  const totalIn = psbt.data.inputs.reduce((s, i) => s + (i.witnessUtxo?.value ?? 0), 0);
  const totalOut = psbt.txOutputs.reduce((s, o) => s + o.value, 0);
  const fee = totalIn - totalOut;
  const MAX_FEE_RATE = 500; // sat/vB
  const vsize = psbt.extractTransaction(true).virtualSize();
  if (fee / vsize > MAX_FEE_RATE) {
    throw new Error(`Fee rate ${(fee / vsize).toFixed(1)} sat/vB exceeds max ${MAX_FEE_RATE}`);
  }

  psbt.signInput(inputIndex, keyPair);
}
```

---

## 0x0007 — Script type / derivation path mismatch

### Vulnerable: Taproot UTXO signed with ECDSA derivation path

```typescript
// VULNERABLE — P2TR input signed with m/84' (P2WPKH) derivation
import * as bitcoin from "bitcoinjs-lib";
import BIP32Factory from "bip32";
import * as ecc from "tiny-secp256k1";

const bip32 = BIP32Factory(ecc);

function signWithWrongDerivation(psbt: bitcoin.Psbt, masterKey: any) {
  const input = psbt.data.inputs[0];
  const scriptPubKey = input.witnessUtxo?.script;

  // Script is P2TR (0x5120 + 32-byte x-only pubkey)
  // But we derive with m/84'/0'/0'/0/0 (P2WPKH path)
  const child = masterKey.derivePath("m/84'/0'/0'/0/0");

  // bitcoinjs-lib may silently use ECDSA instead of Schnorr
  // because the key was derived from a non-Taproot path
  // This produces an invalid signature or worse — signs with wrong algorithm
  psbt.signInput(0, child);
}
```

### Secure: Validate script type matches derivation path

```typescript
function validateAndSign(psbt: bitcoin.Psbt, masterKey: any, inputIndex: number) {
  const input = psbt.data.inputs[inputIndex];
  const scriptPubKey = input.witnessUtxo?.script;
  if (!scriptPubKey) throw new Error("Missing witness UTXO");

  // Detect script type from scriptPubKey
  const scriptType = detectScriptType(scriptPubKey);

  // Map script type to expected derivation purpose
  const expectedPurpose: Record<string, string> = {
    p2pkh: "44'",
    "p2sh-p2wpkh": "49'",
    p2wpkh: "84'",
    p2tr: "86'",
  };

  const bip32Derivation = input.bip32Derivation?.[0];
  if (bip32Derivation) {
    const path = bip32Derivation.path;
    const purpose = path.split("/")[1]; // e.g., "86'"
    if (purpose !== expectedPurpose[scriptType]) {
      throw new Error(
        `Script type ${scriptType} requires derivation purpose ${expectedPurpose[scriptType]}, ` +
          `but got ${purpose}. Possible signing algorithm mismatch.`
      );
    }
  }

  // Use correct signing method
  if (scriptType === "p2tr") {
    const child = masterKey.derivePath("m/86'/0'/0'/0/0");
    psbt.signInput(inputIndex, child); // bitcoinjs-lib auto-detects Schnorr for P2TR
  } else {
    const child = masterKey.derivePath(`m/${expectedPurpose[scriptType]}/0'/0'/0/0`);
    psbt.signInput(inputIndex, child);
  }
}

function detectScriptType(script: Buffer): string {
  if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) return "p2tr";
  if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) return "p2wpkh";
  if (script.length === 23 && script[0] === 0xa9) return "p2sh-p2wpkh";
  if (script.length === 25 && script[0] === 0x76) return "p2pkh";
  throw new Error("Unknown script type");
}
```

---

## 0x0008 — No fee bounds on signing

### Vulnerable: Wallet signs without fee validation

```typescript
// VULNERABLE — no fee ceiling, no fee rate check
import * as bitcoin from "bitcoinjs-lib";

async function signTransaction(psbtBase64: string, keyPair: any): Promise<string> {
  const psbt = bitcoin.Psbt.fromBase64(psbtBase64);

  // Signs all inputs without checking the fee
  for (let i = 0; i < psbt.inputCount; i++) {
    psbt.signInput(i, keyPair);
  }

  psbt.finalizeAllInputs();
  return psbt.extractTransaction().toHex();
  // Could be paying 50% of input value as fees — no check!
}
```

### Secure: Enforce fee bounds before signing

```typescript
const MAX_FEE_ABSOLUTE = 100_000; // 100k sats
const MAX_FEE_RATE = 500; // sat/vB
const MAX_FEE_PERCENT = 10; // 10% of total input value

function validateFees(psbt: bitcoin.Psbt): void {
  const totalIn = psbt.data.inputs.reduce(
    (sum, input) => sum + (input.witnessUtxo?.value ?? 0),
    0
  );
  const totalOut = psbt.txOutputs.reduce((sum, out) => sum + out.value, 0);
  const fee = totalIn - totalOut;

  if (fee < 0) throw new Error("Negative fee — outputs exceed inputs");
  if (fee > MAX_FEE_ABSOLUTE) throw new Error(`Fee ${fee} exceeds absolute max ${MAX_FEE_ABSOLUTE}`);

  const feePercent = (fee / totalIn) * 100;
  if (feePercent > MAX_FEE_PERCENT) throw new Error(`Fee is ${feePercent.toFixed(1)}% of inputs`);

  // Note: virtualSize() requires at least partial finalization to estimate
  // Use weight estimation for pre-sign checks
}
```

---

## 0x0009 — Mempool exposure of partial PSBT

### Vulnerable: Marketplace API leaks signed PSBTs publicly

```typescript
// VULNERABLE — signed seller PSBTs exposed via public API + WebSocket
import express from "express";
import { WebSocketServer } from "ws";

const app = express();
const wss = new WebSocketServer({ port: 8080 });

// Public REST endpoint returns signed seller PSBTs
app.get("/api/listings/:id/psbt", async (req, res) => {
  const listing = await db.getListing(req.params.id);
  // Returns the seller's SIGHASH_SINGLE|ANYONECANPAY signed PSBT
  // Anyone can use this to construct a competing buy transaction
  res.json({ psbt: listing.signedPsbt });
});

// WebSocket broadcasts new listings with signed PSBTs to ALL clients
wss.on("connection", (ws) => {
  db.on("newListing", (listing: any) => {
    // Every connected client gets the signed PSBT — enables snipping
    ws.send(JSON.stringify({ type: "listing", psbt: listing.signedPsbt }));
  });
});
```

### Secure: Commit-reveal with rate limiting

```typescript
app.post("/api/listings/:id/request-psbt", authMiddleware, async (req, res) => {
  // 1. Rate limit per user
  if (await isRateLimited(req.user.id)) {
    return res.status(429).json({ error: "Rate limit exceeded" });
  }

  // 2. Require purchase commitment (deposit or signed intent)
  const { commitmentTx } = req.body;
  if (!verifyPurchaseCommitment(commitmentTx, req.params.id)) {
    return res.status(400).json({ error: "Invalid purchase commitment" });
  }

  // 3. Return PSBT only to committed buyer, not publicly
  const listing = await db.getListing(req.params.id);
  res.json({ psbt: listing.signedPsbt });

  // 4. Lock the listing for a short window
  await db.lockListing(req.params.id, req.user.id, /* 30 seconds */);
});
```

---

## 0x000a — Taproot key-path not disabled (non-NUMS internal key)

### Vulnerable: Multisig Taproot output uses real key as internal key

```typescript
// VULNERABLE — custodian's real key as internal key bypasses script-path multisig
import * as bitcoin from "bitcoinjs-lib";
import { toXOnly } from "bitcoinjs-lib/src/psbt/bip371";
import * as ecc from "tiny-secp256k1";

bitcoin.initEccLib(ecc);

function createMultisigTaprootOutput(
  custodianPubkey: Buffer, // real key — custodian can bypass multisig!
  userPubkey: Buffer
) {
  // Script path: 2-of-2 multisig Tapscript
  const multisigLeaf = bitcoin.script.compile([
    toXOnly(custodianPubkey),
    bitcoin.opcodes.OP_CHECKSIGVERIFY,
    toXOnly(userPubkey),
    bitcoin.opcodes.OP_CHECKSIG,
  ]);

  const scriptTree: bitcoin.Taptree = { output: multisigLeaf };

  // BUG: using custodian's real pubkey as internal key
  // Custodian can spend via key-path without user's signature!
  const { output, address } = bitcoin.payments.p2tr({
    internalPubkey: toXOnly(custodianPubkey), // should be NUMS point
    scriptTree,
    network: bitcoin.networks.bitcoin,
  });

  return { output, address };
}
```

### Secure: Use unspendable NUMS point as internal key

```typescript
// BIP-341 recommended unspendable key: lift_x(SHA256("TapTweak"))
// Has no known discrete log — key-path spending is impossible
const NUMS_POINT = Buffer.from(
  "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
  "hex"
);

function secureMultisigTaproot(custodianPubkey: Buffer, userPubkey: Buffer) {
  const multisigLeaf = bitcoin.script.compile([
    toXOnly(custodianPubkey),
    bitcoin.opcodes.OP_CHECKSIGVERIFY,
    toXOnly(userPubkey),
    bitcoin.opcodes.OP_CHECKSIG,
  ]);

  const scriptTree: bitcoin.Taptree = { output: multisigLeaf };

  const { output, address } = bitcoin.payments.p2tr({
    internalPubkey: NUMS_POINT, // unspendable — forces script-path only
    scriptTree,
    network: bitcoin.networks.bitcoin,
  });

  return { output, address };
}
```

---

## 0x000b — Wrong Taproot tweak hash computation

### Vulnerable: Plain SHA256 instead of tagged hash for TapTweak

```typescript
// VULNERABLE — uses plain SHA256 instead of BIP-341 tagged hash
import { createHash } from "crypto";
import * as ecc from "tiny-secp256k1";

function computeTweakWrong(internalPubkey: Buffer, merkleRoot: Buffer): Buffer {
  // BUG: plain SHA256 instead of tagged_hash("TapTweak", ...)
  return createHash("sha256")
    .update(Buffer.concat([internalPubkey, merkleRoot]))
    .digest();
  // Should be: tagged_hash("TapTweak", internalPubkey || merkleRoot)
  // where tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
}

function tweakKey(internalPubkey: Buffer, merkleRoot: Buffer): Buffer | null {
  const tweak = computeTweakWrong(internalPubkey, merkleRoot);
  // The tweaked key won't match the on-chain output key
  // Signatures will be invalid, potentially locking funds
  return ecc.xOnlyPointAddTweak(internalPubkey, tweak)?.xOnlyPubkey ?? null;
}
```

### Secure: Use BIP-341 tagged hash

```typescript
import { taggedHash } from "bitcoinjs-lib/src/crypto";

function computeTweakCorrect(internalPubkey: Buffer, merkleRoot: Buffer): Buffer {
  // BIP-341: tagged_hash("TapTweak", internal_key || merkle_root)
  return taggedHash("TapTweak", Buffer.concat([internalPubkey, merkleRoot]));
}

// Or use bitcoinjs-lib's built-in p2tr which handles this correctly:
// bitcoin.payments.p2tr({ internalPubkey, scriptTree })
```

---

## 0x000c — MuSig2 nonce reuse across signing sessions

### Vulnerable: Deterministic nonce generation for MuSig2

```typescript
// VULNERABLE — nonce derived deterministically from message (RFC 6979 style)
// This is SAFE for single-signer Schnorr but CATASTROPHIC for MuSig2
import { createHmac, randomBytes } from "crypto";

class MuSig2Signer {
  private privateKey: Buffer;

  constructor(privateKey: Buffer) {
    this.privateKey = privateKey;
  }

  generateNonce(message: Buffer): { secretNonce: Buffer; publicNonce: Buffer } {
    // BUG: deterministic nonce — a co-signer can influence the message
    // to get the same nonce used for a different signing session
    const k = createHmac("sha256", this.privateKey).update(message).digest();
    // If attacker triggers two sessions with same message hash → nonce reuse → key extraction

    const R = ecc.pointFromScalar(k);
    return { secretNonce: k, publicNonce: Buffer.from(R!) };
  }

  // Also vulnerable: caching nonces for retry
  private nonceCache = new Map<string, Buffer>();

  generateNonceCached(sessionId: string): Buffer {
    if (this.nonceCache.has(sessionId)) {
      return this.nonceCache.get(sessionId)!; // reusing old nonce on retry!
    }
    const k = randomBytes(32);
    this.nonceCache.set(sessionId, k);
    return k;
    // If session is aborted and restarted with same ID, nonce is reused
  }
}
```

### Secure: Fresh CSPRNG nonce with use-once enforcement

```typescript
class SecureMuSig2Signer {
  private privateKey: Buffer;
  private usedNonces = new Set<string>();

  generateNonce(): { secretNonce: Buffer; publicNonce: Buffer } {
    // Fresh CSPRNG randomness — never derived from message
    const k = randomBytes(32);
    const nonceId = createHash("sha256").update(k).digest("hex");
    this.usedNonces.add(nonceId);

    const R = ecc.pointFromScalar(k);
    return { secretNonce: k, publicNonce: Buffer.from(R!) };
  }

  sign(secretNonce: Buffer, challenge: Buffer): Buffer {
    const nonceId = createHash("sha256").update(secretNonce).digest("hex");

    // Use-once enforcement
    if (!this.usedNonces.has(nonceId)) {
      throw new Error("Unknown nonce — refusing to sign");
    }
    this.usedNonces.delete(nonceId); // consumed — cannot be reused

    // Compute partial signature
    const s = /* schnorr partial sig computation */;
    // Securely erase nonce from memory
    secretNonce.fill(0);
    return s;
  }
}
```

---

## 0x000d — Partial signatures not validated before aggregation

### Vulnerable: Aggregator accepts partial sigs without verification

```typescript
// VULNERABLE — no PartialSigVerify before aggregation
class MuSig2Aggregator {
  aggregateSignatures(
    partialSigs: Buffer[],
    publicKeys: Buffer[],
    aggregateNonce: Buffer,
    message: Buffer
  ): Buffer {
    // BUG: no verification of individual partial signatures
    // A malicious signer can submit a crafted partial sig that
    // makes the aggregate valid on a DIFFERENT message

    // Also BUG: plain key summation instead of BIP-327 KeyAgg with coefficients
    const aggregateKey = publicKeys.reduce(
      (sum, pk) => ecc.pointAdd(sum, pk)!,
      publicKeys[0]
    );
    // Missing: KeyAgg coefficients prevent rogue-key attacks

    // Simple summation of partial sigs (mod n)
    let aggregateSig = BigInt(0);
    for (const sig of partialSigs) {
      aggregateSig = (aggregateSig + BigInt("0x" + sig.toString("hex"))) % CURVE_ORDER;
    }

    return Buffer.concat([aggregateNonce, bigintToBuffer(aggregateSig)]);
  }
}
```

### Secure: Validate each partial sig + use KeyAgg coefficients

```typescript
class SecureMuSig2Aggregator {
  aggregateSignatures(
    partialSigs: Buffer[],
    publicNonces: Buffer[],
    publicKeys: Buffer[],
    message: Buffer
  ): Buffer {
    // 1. Compute KeyAgg with BIP-327 coefficients (rogue-key protection)
    const keyAggCtx = musig2KeyAgg(publicKeys);

    // 2. Compute aggregate nonce
    const aggNonce = musig2NonceAgg(publicNonces);

    // 3. Verify each partial signature BEFORE aggregation
    for (let i = 0; i < partialSigs.length; i++) {
      const valid = musig2PartialSigVerify(
        partialSigs[i],
        publicNonces[i],
        publicKeys[i],
        keyAggCtx,
        aggNonce,
        message
      );
      if (!valid) {
        throw new Error(`Invalid partial signature from signer ${i} — possible rogue-key attack`);
      }
    }

    // 4. Safe to aggregate
    return musig2PartialSigAgg(partialSigs, aggNonce);
  }
}
```

---

## 0x000e — Shared mutable session state across concurrent signings

### Vulnerable: Global mutable state for MuSig2 sessions

```typescript
// VULNERABLE — shared mutable state, no session isolation
const GLOBAL_SESSIONS: Record<string, MuSig2Session> = {};
const GLOBAL_NONCE_STORE: Record<string, Buffer> = {};

class MuSig2SessionManager {
  createSession(sessionId: string, participants: Buffer[]) {
    // No unique session ID validation — attacker can guess/reuse IDs
    GLOBAL_SESSIONS[sessionId] = {
      participants,
      nonces: {},
      partialSigs: {},
      status: "pending",
    };
  }

  storeNonce(sessionId: string, signerIndex: number, nonce: Buffer) {
    // BUG: shared global store with no locking
    // Concurrent sessions can overwrite each other's nonces
    GLOBAL_NONCE_STORE[`${sessionId}:${signerIndex}`] = nonce;
  }

  // No session timeout — stale sessions persist forever
  // No cleanup of nonce material after use
  // No isolation between concurrent sessions
}
```

### Secure: Isolated session state with crypto-random IDs and timeouts

```typescript
class SecureSessionManager {
  private sessions = new Map<string, MuSig2Session>();
  private readonly SESSION_TIMEOUT_MS = 60_000; // 1 minute

  createSession(participants: Buffer[]): string {
    // Crypto-random session ID — unguessable
    const sessionId = randomBytes(32).toString("hex");

    this.sessions.set(sessionId, {
      participants,
      nonces: new Map(), // per-session nonce storage
      partialSigs: new Map(),
      status: "pending",
      createdAt: Date.now(),
    });

    // Auto-cleanup after timeout
    setTimeout(() => this.destroySession(sessionId), this.SESSION_TIMEOUT_MS);
    return sessionId;
  }

  destroySession(sessionId: string) {
    const session = this.sessions.get(sessionId);
    if (session) {
      // Securely erase all nonce material
      for (const nonce of session.nonces.values()) {
        nonce.fill(0);
      }
      this.sessions.delete(sessionId);
    }
  }
}
```

---

## 0x000f — Incomplete finalization (missing sig check)

### Vulnerable: Finalizer doesn't validate signatures before building witness

```typescript
// VULNERABLE — finalizes without checking signature count or validity
import * as bitcoin from "bitcoinjs-lib";

function unsafeFinalize(psbt: bitcoin.Psbt): string {
  // Just calls finalizeAllInputs without pre-checks
  try {
    psbt.finalizeAllInputs();
  } catch (e) {
    // Swallows errors and tries partial finalization
    for (let i = 0; i < psbt.inputCount; i++) {
      try {
        psbt.finalizeInput(i);
      } catch {
        // BUG: skips inputs that fail finalization
        // May produce a TX with incomplete witnesses
      }
    }
  }

  const tx = psbt.extractTransaction();
  // tx may have invalid/missing witnesses for some inputs
  // Broadcasting this wastes fees or creates exploitable conditions
  return tx.toHex();
}
```

### Secure: Validate all signatures before finalization

```typescript
function safeFinalize(psbt: bitcoin.Psbt): string {
  // 1. Check all inputs have required signatures
  for (let i = 0; i < psbt.inputCount; i++) {
    const input = psbt.data.inputs[i];

    // Check for partial sigs
    const sigCount = input.partialSig?.length ?? 0;
    const tapKeySig = input.tapKeySig ? 1 : 0;
    const tapScriptSig = input.tapScriptSig?.length ?? 0;

    if (sigCount === 0 && tapKeySig === 0 && tapScriptSig === 0) {
      throw new Error(`Input ${i} has no signatures — cannot finalize`);
    }

    // For multisig, verify threshold
    if (input.witnessScript) {
      const decompiled = bitcoin.script.decompile(input.witnessScript);
      if (decompiled) {
        const requiredSigs = (decompiled[0] as number) - bitcoin.opcodes.OP_1 + 1;
        if (sigCount < requiredSigs) {
          throw new Error(`Input ${i}: ${sigCount}/${requiredSigs} sigs — threshold not met`);
        }
      }
    }
  }

  // 2. Validate signatures against sighash
  psbt.validateSignaturesOfAllInputs((pubkey, msghash, signature) => {
    return ecc.verify(msghash, pubkey, signature);
  });

  // 3. Finalize
  psbt.finalizeAllInputs();

  // 4. Test before broadcast
  const tx = psbt.extractTransaction();
  return tx.toHex();
}
```

---

## 0x0010 — Malformed PSBT deserialization

### Vulnerable: No bounds checking on PSBT parsing

```typescript
// VULNERABLE — parses untrusted PSBT without validation
import * as bitcoin from "bitcoinjs-lib";

app.post("/api/sign", async (req, res) => {
  const { psbtBase64 } = req.body;

  try {
    // bitcoinjs-lib's Psbt.fromBase64 does basic parsing but...
    const psbt = bitcoin.Psbt.fromBase64(psbtBase64);

    // No timelock validation
    const tx = (psbt as any).__CACHE.__TX as bitcoin.Transaction;
    // nLockTime could be set to year 2099 — funds locked forever
    // nSequence could be 0xFFFFFFFF on all inputs — disabling nLockTime

    // No size limits — could be a massive PSBT causing OOM
    // No duplicate key detection beyond what bitcoinjs-lib does internally

    // Signs without additional validation
    psbt.signAllInputs(serverKeyPair);
    res.json({ psbt: psbt.toBase64() });
  } catch (e) {
    res.status(400).json({ error: "Invalid PSBT" });
  }
});
```

### Secure: Comprehensive pre-sign PSBT validation

```typescript
function validatePsbtStructure(psbtBase64: string): bitcoin.Psbt {
  // 1. Size limit before parsing
  const raw = Buffer.from(psbtBase64, "base64");
  if (raw.length > 1_000_000) {
    throw new Error("PSBT exceeds maximum size (1MB)");
  }

  // 2. Magic bytes check
  if (raw.slice(0, 5).toString("hex") !== "70736274ff") {
    throw new Error("Invalid PSBT magic bytes");
  }

  const psbt = bitcoin.Psbt.fromBuffer(raw);

  // 3. Timelock validation
  const locktime = psbt.locktime;
  if (locktime > 0) {
    const currentBlock = getCurrentBlockHeight();
    if (locktime > currentBlock + 52560) {
      // > ~1 year from now
      throw new Error(`Suspicious nLockTime: ${locktime} is far in the future`);
    }
  }

  // 4. Check nSequence consistency with timelocks
  const allMaxSequence = psbt.txInputs.every((i) => i.sequence === 0xffffffff);
  if (locktime > 0 && allMaxSequence) {
    throw new Error("nLockTime set but all inputs have max sequence — timelock is disabled");
  }

  // 5. Input/output count sanity
  if (psbt.inputCount > 500 || psbt.txOutputs.length > 500) {
    throw new Error("Excessive input/output count");
  }

  return psbt;
}
```

---

## Quick Reference: Import Patterns to Flag

| Pattern | Risk | Checkpoint |
|---------|------|------------|
| `SIGHASH_NONE` or `sighashType: 0x02` | Output theft | 0x0000 |
| `SIGHASH_SINGLE` without index check | anyone-can-spend | 0x0001 |
| `sighashType: 0x82` (ACP\|NONE) | Total hijack | 0x0002 |
| `psbt.addInput` after `psbt.signInput` | Input injection | 0x0003 |
| Output modification between signing rounds | Change theft | 0x0004 |
| No `SHA256d` comparison for `nonWitnessUtxo` | UTXO spoofing | 0x0005 |
| No cross-reference for `witnessUtxo.value` | Fee overpayment | 0x0006 |
| Mismatched derivation path / script type | Wrong algorithm | 0x0007 |
| No fee bounds before `psbt.signInput` | Fee extraction | 0x0008 |
| `signedPsbt` in public API/WebSocket | Snipping attack | 0x0009 |
| Real pubkey as `internalPubkey` in `p2tr()` | Key-path bypass | 0x000a |
| `createHash("sha256")` for TapTweak | Wrong tweak | 0x000b |
| Deterministic nonce in MuSig2 | Key extraction | 0x000c |
| No `PartialSigVerify` before aggregation | Rogue-key attack | 0x000d |
| Shared global `SESSIONS` / `NONCE_STORE` | Cross-session leak | 0x000e |
| `finalizeAllInputs()` without sig validation | Invalid broadcast | 0x000f |
| No size/timelock/magic validation on parse | DoS/lockup | 0x0010 |
