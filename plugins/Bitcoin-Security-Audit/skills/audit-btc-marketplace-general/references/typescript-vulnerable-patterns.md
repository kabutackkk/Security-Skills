# TypeScript Vulnerable Patterns for BTC Marketplace Audits

Real-world vulnerable TypeScript patterns for Ordinals/BRC-20/Runes marketplaces using `bitcoinjs-lib`, `ord` indexer APIs, `@magiceden/ord-sdk`, and common marketplace backend patterns. Each section maps to a checkpoint.

---

## 0x0000 — Listing PSBT sighash grants excessive modification rights

### Vulnerable: Listing builder uses SIGHASH_NONE|ANYONECANPAY

```typescript
// VULNERABLE — wrong sighash gives buyer total control over outputs
import * as bitcoin from "bitcoinjs-lib";

async function createListing(
  inscriptionUtxo: UTXO,
  sellerKeyPair: any,
  priceInSats: number
) {
  const psbt = new bitcoin.Psbt({ network: bitcoin.networks.bitcoin });

  psbt.addInput({
    hash: inscriptionUtxo.txid,
    index: inscriptionUtxo.vout,
    witnessUtxo: {
      script: Buffer.from(inscriptionUtxo.scriptPubKey, "hex"),
      value: inscriptionUtxo.value,
    },
    // BUG: SIGHASH_NONE|ANYONECANPAY (0x82) — commits to NOTHING
    // Buyer can replace all outputs, taking inscription without payment
    sighashType: 0x82,
  });

  psbt.addOutput({ address: sellerAddress, value: priceInSats });
  psbt.signInput(0, sellerKeyPair, [0x82]);
  return psbt.toBase64();
}
```

### Secure: Always SIGHASH_SINGLE|ANYONECANPAY with index alignment

```typescript
async function secureListing(inscriptionUtxo: UTXO, sellerKeyPair: any, priceInSats: number) {
  const psbt = new bitcoin.Psbt({ network: bitcoin.networks.bitcoin });
  const SIGHASH_SINGLE_ACP = bitcoin.Transaction.SIGHASH_SINGLE | bitcoin.Transaction.SIGHASH_ANYONECANPAY;

  // Input index 0 → payment output must also be at index 0
  psbt.addInput({
    hash: inscriptionUtxo.txid,
    index: inscriptionUtxo.vout,
    witnessUtxo: { script: Buffer.from(inscriptionUtxo.scriptPubKey, "hex"), value: inscriptionUtxo.value },
    sighashType: SIGHASH_SINGLE_ACP, // 0x83 — commits to own input + matched output
  });

  // Payment output at index 0 (same as input index)
  psbt.addOutput({ address: sellerAddress, value: priceInSats });
  psbt.signInput(0, sellerKeyPair, [SIGHASH_SINGLE_ACP]);
  return psbt.toBase64();
}
```

---

## 0x0001 — Stale listing PSBT replayable after off-chain cancel

### Vulnerable: Cancel only removes DB entry, UTXO remains spendable

```typescript
// VULNERABLE — off-chain-only cancellation, stale PSBT still valid
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function cancelListing(listingId: string, sellerId: string) {
  // Only deletes from database — the signed PSBT is still valid on-chain!
  await prisma.listing.delete({ where: { id: listingId, sellerId } });

  // A buyer who cached the PSBT can still complete the trade
  // at the old price, because the inscription UTXO is unspent
  return { success: true, message: "Listing cancelled" };
}

// Price update also vulnerable — old lower-price PSBT still works
async function updateListingPrice(listingId: string, newPrice: number) {
  await prisma.listing.update({
    where: { id: listingId },
    data: { price: newPrice }, // DB updated, but old PSBT with old price is still valid
  });
}
```

### Secure: On-chain cancel (spend the UTXO to self)

```typescript
async function secureCancel(listingId: string, sellerKeyPair: any) {
  const listing = await prisma.listing.findUnique({ where: { id: listingId } });
  if (!listing) throw new Error("Listing not found");

  // Spend the inscription UTXO to a new address owned by seller
  // This invalidates ANY signed PSBT referencing this UTXO
  const cancelPsbt = new bitcoin.Psbt({ network: bitcoin.networks.bitcoin });

  cancelPsbt.addInput({
    hash: listing.utxoTxid,
    index: listing.utxoVout,
    witnessUtxo: { script: Buffer.from(listing.scriptPubKey, "hex"), value: listing.utxoValue },
  });

  // Send inscription to new address (self-transfer)
  cancelPsbt.addOutput({
    address: await deriveNewAddress(sellerKeyPair),
    value: listing.utxoValue, // minus fee
  });

  cancelPsbt.signInput(0, sellerKeyPair);
  cancelPsbt.finalizeAllInputs();
  const cancelTx = cancelPsbt.extractTransaction();
  await broadcastTransaction(cancelTx.toHex());

  // Now delete from DB — the UTXO is spent, old PSBT is invalid
  await prisma.listing.delete({ where: { id: listingId } });
}
```

---

## 0x0002 — Buyer completion allows fee manipulation

### Vulnerable: Server-side buyer PSBT construction with no fee ceiling

```typescript
// VULNERABLE — server controls fee rate with no upper bound
async function completePurchase(listingId: string, buyerUtxos: UTXO[], buyerAddress: string) {
  const listing = await getListingPsbt(listingId);
  const psbt = bitcoin.Psbt.fromBase64(listing.psbtBase64);

  // Server adds buyer inputs
  for (const utxo of buyerUtxos) {
    psbt.addInput({
      hash: utxo.txid,
      index: utxo.vout,
      witnessUtxo: { script: Buffer.from(utxo.scriptPubKey, "hex"), value: utxo.value },
    });
  }

  const totalBuyerInput = buyerUtxos.reduce((s, u) => s + u.value, 0);

  // Inscription delivery output
  psbt.addOutput({ address: buyerAddress, value: 546 });
  // Platform fee (2.5%)
  psbt.addOutput({ address: platformFeeAddress, value: Math.floor(listing.price * 0.025) });
  // Change — BUG: no fee rate validation, server could inflate the fee
  const feeRate = await getServerFeeRate(); // server-controlled, no ceiling!
  const estimatedSize = 250; // rough estimate
  const fee = feeRate * estimatedSize;
  const change = totalBuyerInput - listing.price - 546 - Math.floor(listing.price * 0.025) - fee;

  if (change > 546) {
    psbt.addOutput({ address: buyerAddress, value: change });
  }
  // If fee is inflated, the "missing" change is absorbed as miner fee
  return psbt.toBase64();
}
```

### Secure: Client-verified fee bounds

```typescript
const MAX_FEE_RATE = 200; // sat/vB
const MAX_FEE_PERCENT = 5; // 5% of total value

function validateBuyerCompletion(psbt: bitcoin.Psbt, expectedPrice: number) {
  const totalIn = psbt.data.inputs.reduce((s, i) => s + (i.witnessUtxo?.value ?? 0), 0);
  const totalOut = psbt.txOutputs.reduce((s, o) => s + o.value, 0);
  const fee = totalIn - totalOut;

  if (fee / totalIn > MAX_FEE_PERCENT / 100) {
    throw new Error(`Fee is ${((fee / totalIn) * 100).toFixed(1)}% of input — exceeds ${MAX_FEE_PERCENT}%`);
  }

  // Verify inscription delivery output exists
  const hasInscriptionDelivery = psbt.txOutputs.some((o) => o.value === 546);
  if (!hasInscriptionDelivery) {
    throw new Error("Missing inscription delivery output");
  }
}
```

---

## 0x0003 — No cardinal/ordinal UTXO separation

### Vulnerable: UTXO selector doesn't distinguish inscription UTXOs

```typescript
// VULNERABLE — treats all UTXOs as fungible
async function selectUtxosForPayment(walletAddress: string, targetAmount: number): Promise<UTXO[]> {
  const allUtxos = await fetchUtxos(walletAddress);

  // Sorts by value descending and picks greedily — no inscription awareness
  const sorted = allUtxos.sort((a, b) => b.value - a.value);
  const selected: UTXO[] = [];
  let total = 0;

  for (const utxo of sorted) {
    selected.push(utxo); // might select an inscription-bearing UTXO as fee input!
    total += utxo.value;
    if (total >= targetAmount) break;
  }

  return selected;
  // An inscription UTXO used as payment input → inscription destroyed
}
```

### Secure: Separate cardinal and ordinal UTXO pools

```typescript
async function selectCardinalUtxos(walletAddress: string, targetAmount: number): Promise<UTXO[]> {
  const allUtxos = await fetchUtxos(walletAddress);

  // Query indexer for inscription-bearing UTXOs
  const inscriptionUtxos = await fetchInscriptionUtxos(walletAddress);
  const inscriptionOutpoints = new Set(
    inscriptionUtxos.map((u: UTXO) => `${u.txid}:${u.vout}`)
  );

  // Filter to cardinal-only UTXOs
  const cardinalUtxos = allUtxos.filter(
    (u) => !inscriptionOutpoints.has(`${u.txid}:${u.vout}`)
  );

  // Additional safety: exclude all UTXOs at 546 sats (common inscription value)
  const safeUtxos = cardinalUtxos.filter((u) => u.value > 1000);

  const sorted = safeUtxos.sort((a, b) => b.value - a.value);
  const selected: UTXO[] = [];
  let total = 0;

  for (const utxo of sorted) {
    selected.push(utxo);
    total += utxo.value;
    if (total >= targetAmount) break;
  }

  if (total < targetAmount) {
    throw new Error("Insufficient cardinal (non-inscription) UTXOs");
  }
  return selected;
}
```

---

## 0x0004 — Inscription UTXO used as padding/fee input

### Vulnerable: Padding selector draws from unfiltered UTXO pool

```typescript
// VULNERABLE — padding UTXO picker includes inscription UTXOs
async function addPaddingInputs(
  psbt: bitcoin.Psbt,
  walletAddress: string,
  additionalSatsNeeded: number
) {
  const utxos = await fetchUtxos(walletAddress);

  // Picks smallest UTXOs first for padding — inscription UTXOs are often 546 sats
  const sorted = utxos.sort((a, b) => a.value - b.value);

  let added = 0;
  for (const utxo of sorted) {
    if (added >= additionalSatsNeeded) break;

    // No check for inscription content!
    // 546-sat UTXOs are very likely to contain inscriptions
    psbt.addInput({
      hash: utxo.txid,
      index: utxo.vout,
      witnessUtxo: { script: Buffer.from(utxo.scriptPubKey, "hex"), value: utxo.value },
    });
    added += utxo.value;
  }
}
```

### Secure: Quarantine inscription UTXOs and flag zero-conf

```typescript
async function safeAddPadding(psbt: bitcoin.Psbt, walletAddress: string, needed: number) {
  const utxos = await fetchUtxos(walletAddress);
  const inscriptions = await fetchInscriptionUtxos(walletAddress);
  const inscriptionSet = new Set(inscriptions.map((u: UTXO) => `${u.txid}:${u.vout}`));

  const safeUtxos = utxos.filter((u) => {
    if (inscriptionSet.has(`${u.txid}:${u.vout}`)) return false; // inscription
    if (u.value <= 546) return false; // likely inscription
    if (u.confirmations === 0) return false; // zero-conf — not safe for padding
    return true;
  });

  let added = 0;
  for (const utxo of safeUtxos.sort((a, b) => a.value - b.value)) {
    if (added >= needed) break;
    psbt.addInput({
      hash: utxo.txid,
      index: utxo.vout,
      witnessUtxo: { script: Buffer.from(utxo.scriptPubKey, "hex"), value: utxo.value },
    });
    added += utxo.value;
  }

  if (added < needed) throw new Error("Insufficient safe (non-inscription) UTXOs for padding");
}
```

---

## 0x0005 — Single indexer trust without cross-reference

### Vulnerable: Marketplace trusts a single ord indexer for all state

```typescript
// VULNERABLE — single indexer, no cross-reference
const ORD_API = "https://ord-indexer.example.com";

async function getInscriptionOwner(inscriptionId: string): Promise<string> {
  const resp = await fetch(`${ORD_API}/inscription/${inscriptionId}`);
  const data = await resp.json();
  // Trusts a single indexer — if it's wrong, trades execute on false state
  return data.address;
}

async function getBrc20Balance(address: string, ticker: string): Promise<number> {
  const resp = await fetch(`${ORD_API}/brc-20/balances/${address}?ticker=${ticker}`);
  const data = await resp.json();
  // Single source of truth — different indexers may report different balances
  return data.availableBalance;
}

async function validateListing(listing: Listing): Promise<boolean> {
  const owner = await getInscriptionOwner(listing.inscriptionId);
  // If indexer is out of sync or buggy, we might approve a listing
  // where the seller no longer owns the inscription
  return owner === listing.sellerAddress;
}
```

### Secure: Multi-indexer cross-reference with consensus check

```typescript
const INDEXERS = [
  { name: "ord", url: "https://ord.example.com" },
  { name: "hiro", url: "https://api.hiro.so/ordinals/v1" },
  { name: "unisat", url: "https://open-api.unisat.io/v1" },
];

async function verifiedGetInscriptionOwner(inscriptionId: string): Promise<string> {
  const results = await Promise.allSettled(
    INDEXERS.map(async (idx) => {
      const resp = await fetch(`${idx.url}/inscription/${inscriptionId}`);
      return { indexer: idx.name, address: (await resp.json()).address };
    })
  );

  const successes = results.filter((r) => r.status === "fulfilled").map((r) => (r as any).value);

  if (successes.length < 2) {
    throw new Error("Cannot verify inscription — fewer than 2 indexers responded");
  }

  const addresses = new Set(successes.map((s: any) => s.address));
  if (addresses.size > 1) {
    throw new Error(
      `Indexer disagreement on inscription owner: ${JSON.stringify(successes)}. ` +
        `Trade blocked until consensus is reached.`
    );
  }

  return successes[0].address;
}
```

---

## 0x0006 — BRC-20 transfer inscription not validated against consensus

### Vulnerable: Accepts transfer inscription without validity checks

```typescript
// VULNERABLE — no validation of BRC-20 transfer inscription validity
async function processBrc20Trade(
  transferInscriptionId: string,
  expectedTicker: string,
  expectedAmount: number
) {
  const inscription = await fetchInscription(transferInscriptionId);
  const content = JSON.parse(inscription.content);

  // Basic field check only
  if (content.p !== "brc-20" || content.op !== "transfer") {
    throw new Error("Not a BRC-20 transfer");
  }

  // BUG: no check that transfer amount <= available balance
  // BUG: no check that this transfer inscription hasn't already been used
  // BUG: no check for pending transfers that reduce available balance
  // BUG: no cross-indexer validation of balance state

  return {
    ticker: content.tick,
    amount: parseInt(content.amt),
    valid: true, // assumed valid without verification!
  };
}
```

### Secure: Full BRC-20 state machine validation

```typescript
async function verifiedBrc20Trade(
  transferInscriptionId: string,
  sellerAddress: string,
  expectedTicker: string,
  expectedAmount: number
) {
  const inscription = await fetchInscription(transferInscriptionId);
  const content = JSON.parse(inscription.content);

  // 1. Format validation
  if (content.p !== "brc-20" || content.op !== "transfer") throw new Error("Not a BRC-20 transfer");
  if (content.tick !== expectedTicker) throw new Error("Ticker mismatch");
  if (parseInt(content.amt) < expectedAmount) throw new Error("Amount insufficient");

  // 2. Check inscription is not already consumed (transferred)
  const utxoStatus = await fetchUtxoStatus(inscription.outputTxid, inscription.outputVout);
  if (utxoStatus.spent) throw new Error("Transfer inscription already spent (consumed)");

  // 3. Verify seller's available balance covers the transfer
  const balance = await verifiedGetBrc20Balance(sellerAddress, expectedTicker);
  if (balance.available < expectedAmount) {
    throw new Error(`Seller available balance ${balance.available} < transfer amount ${expectedAmount}`);
  }

  // 4. Check for pending transfers that reduce available balance
  if (balance.transferable > 0) {
    console.warn(`Seller has ${balance.transferable} in pending transfers — verify no double-spend`);
  }

  return { valid: true, ticker: content.tick, amount: parseInt(content.amt) };
}
```

---

## 0x0007 — Malformed Runes Runestone not detected

### Vulnerable: Runestone builder with out-of-order tags and bad varint

```typescript
// VULNERABLE — constructs malformed Runestone that becomes a cenotaph
function buildRuneTransfer(runeId: string, amount: bigint, outputIndex: number): Buffer {
  const [block, txIndex] = runeId.split(":").map(Number);

  // BUG 1: tags out of canonical order (Runes spec requires ascending tag order)
  const payload = Buffer.concat([
    encodeTag(2), encodeLeb128(BigInt(block)),   // Rune ID (body tag = 2)
    encodeTag(0), encodeLeb128(BigInt(0)),        // Tag 0 after tag 2 — out of order!
  ]);

  // BUG 2: invalid LEB128 varint at 128 boundary
  // Values >= 128 need multi-byte encoding but this uses single byte
  // Result: Runestone becomes a cenotaph, burning the Runes

  return bitcoin.script.compile([
    bitcoin.opcodes.OP_RETURN,
    Buffer.from("RUNE_TEST"), // also wrong — should be specific magic bytes
    payload,
  ]);
}

// BUG 3: edict output index not validated against TX output count
function buildEdict(runeId: bigint, amount: bigint, outputIndex: number) {
  // outputIndex could be >= actual output count → cenotaph
  return { id: runeId, amount, output: outputIndex };
}
```

### Secure: Validate Runestone before inclusion

```typescript
function validateRunestone(runestone: Buffer, outputCount: number): boolean {
  // 1. Verify magic bytes
  const decompiled = bitcoin.script.decompile(runestone);
  if (!decompiled || decompiled[0] !== bitcoin.opcodes.OP_RETURN) return false;

  // 2. Parse and validate tag ordering
  const tags = parseRunestoneTags(runestone);
  for (let i = 1; i < tags.length; i++) {
    if (tags[i].tag < tags[i - 1].tag) {
      throw new Error(`Tags out of order: ${tags[i - 1].tag} before ${tags[i].tag} — creates cenotaph`);
    }
  }

  // 3. Validate edict output indices
  for (const edict of tags.filter((t) => t.tag === 0)) {
    if (edict.output >= outputCount) {
      throw new Error(`Edict output ${edict.output} >= TX output count ${outputCount} — creates cenotaph`);
    }
  }

  return true;
}
```

---

## 0x0008 — Inscription content rendered without sanitization

### Vulnerable: Inline SVG and HTML rendered unsandboxed

```typescript
// VULNERABLE — inscription content rendered without sanitization
import express from "express";

const app = express();

app.get("/inscription/:id/content", async (req, res) => {
  const inscription = await fetchInscriptionContent(req.params.id);

  // Serves raw content with original content-type — XSS vector
  res.set("Content-Type", inscription.contentType); // could be text/html or image/svg+xml
  res.send(inscription.content);
  // SVG: can contain <script> tags, event handlers
  // HTML: full JS execution in marketplace origin
  // No CSP headers, no sandboxing
});

// Frontend embeds inscription content directly
// <iframe src="/inscription/${id}/content" /> — same origin, no sandbox
```

### Secure: Sandboxed rendering with CSP

```typescript
app.get("/inscription/:id/content", async (req, res) => {
  const inscription = await fetchInscriptionContent(req.params.id);

  // 1. Validate content-type against allowlist
  const SAFE_TYPES = ["image/png", "image/jpeg", "image/gif", "image/webp", "text/plain"];
  const SANDBOXED_TYPES = ["image/svg+xml", "text/html"];

  if (SAFE_TYPES.includes(inscription.contentType)) {
    res.set("Content-Type", inscription.contentType);
    res.set("Content-Security-Policy", "default-src 'none'; img-src 'self'");
    res.send(inscription.content);
  } else if (SANDBOXED_TYPES.includes(inscription.contentType)) {
    // Serve from separate origin with strict CSP
    res.set("Content-Type", inscription.contentType);
    res.set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox");
    res.set("X-Content-Type-Options", "nosniff");
    // Also: verify content-type matches actual magic bytes
    if (!verifyMagicBytes(inscription.content, inscription.contentType)) {
      return res.status(400).send("Content-type mismatch");
    }
    res.send(inscription.content);
  } else {
    res.status(415).send("Unsupported content type");
  }
});

// Frontend: sandboxed iframe on different origin
// <iframe src="https://content.marketplace-cdn.com/inscription/${id}" sandbox="allow-scripts" />
```

---

## 0x0009 — No snipping mitigation on public listings

### Vulnerable: Signed PSBTs publicly accessible, no time-bounding

```typescript
// VULNERABLE — any client can fetch signed PSBT and front-run buyers
app.get("/api/listings", async (req, res) => {
  const listings = await prisma.listing.findMany({
    include: { signedPsbt: true }, // full signed PSBT in response!
  });

  // Snippers monitor this endpoint, race legitimate buyers with higher fees
  res.json(listings);
});

// WebSocket pushes new listings with full PSBTs to all clients
wss.on("connection", (ws) => {
  listingEmitter.on("new", (listing: any) => {
    ws.send(JSON.stringify({ type: "listing", psbt: listing.signedPsbt }));
  });
});
```

### Secure: Commit-reveal with time-bounded purchase window

```typescript
// Phase 1: Buyer commits to purchase (hash of intent)
app.post("/api/listings/:id/commit", authMiddleware, rateLimit, async (req, res) => {
  const { commitmentHash } = req.body; // SHA256(buyer_address + listing_id + nonce)

  await prisma.purchaseCommitment.create({
    data: {
      listingId: req.params.id,
      buyerId: req.user.id,
      commitmentHash,
      expiresAt: new Date(Date.now() + 30_000), // 30-second window
    },
  });
  res.json({ committed: true });
});

// Phase 2: Buyer reveals and gets PSBT (only during commitment window)
app.post("/api/listings/:id/reveal", authMiddleware, async (req, res) => {
  const { nonce, buyerAddress } = req.body;
  const commitment = await prisma.purchaseCommitment.findFirst({
    where: { listingId: req.params.id, buyerId: req.user.id, expiresAt: { gte: new Date() } },
  });

  if (!commitment) return res.status(410).json({ error: "No valid commitment" });

  const expectedHash = sha256(`${buyerAddress}${req.params.id}${nonce}`);
  if (expectedHash !== commitment.commitmentHash) {
    return res.status(400).json({ error: "Commitment mismatch" });
  }

  // Only now release the signed PSBT to this specific buyer
  const listing = await prisma.listing.findUnique({ where: { id: req.params.id } });
  res.json({ psbt: listing!.signedPsbt });
});
```

---

## 0x000a — Mempool exposure enables sandwich attacks

### Vulnerable: Immediate broadcast with RBF enabled

```typescript
// VULNERABLE — broadcasts to public mempool with RBF, enabling sandwich
async function broadcastPurchase(signedPsbtBase64: string) {
  const psbt = bitcoin.Psbt.fromBase64(signedPsbtBase64);
  psbt.finalizeAllInputs();
  const tx = psbt.extractTransaction();

  // All inputs have nSequence = 0xFFFFFFFD (RBF enabled by default in bitcoinjs-lib)
  // Attacker can observe mempool, submit a replacement TX with higher fee

  const result = await fetch("https://mempool.space/api/tx", {
    method: "POST",
    body: tx.toHex(),
  });
  return result.text();
}
```

### Secure: Disable RBF + use private relay

```typescript
async function secureBroadcast(signedPsbtBase64: string) {
  const psbt = bitcoin.Psbt.fromBase64(signedPsbtBase64);

  // Disable RBF by setting nSequence to max (0xFFFFFFFF)
  for (let i = 0; i < psbt.inputCount; i++) {
    psbt.setInputSequence(i, 0xffffffff);
  }

  psbt.finalizeAllInputs();
  const tx = psbt.extractTransaction();

  // Use private relay / mining pool API instead of public mempool
  const result = await fetch("https://private-relay.example.com/api/submit", {
    method: "POST",
    headers: { Authorization: `Bearer ${RELAY_API_KEY}` },
    body: tx.toHex(),
  });
  return result.text();
}
```

---

## 0x000b — Fee/royalty outputs not enforced immutably

### Vulnerable: Fee validation exists but is bypassed on direct PSBT submission

```typescript
// VULNERABLE — validation function exists but isn't called on all paths
function validateFeeOutputs(psbt: bitcoin.Psbt, listing: Listing): boolean {
  const outputs = psbt.txOutputs;
  const platformFee = outputs.find((o) => o.address === PLATFORM_FEE_ADDRESS);
  const royalty = outputs.find((o) => o.address === listing.royaltyAddress);

  if (!platformFee || platformFee.value < Math.floor(listing.price * 0.025)) return false;
  if (listing.royaltyAddress && (!royalty || royalty.value < Math.floor(listing.price * listing.royaltyPct / 100))) return false;
  return true;
}

// Direct PSBT submission endpoint — BYPASSES validation!
app.post("/api/submit-psbt", async (req, res) => {
  const psbt = bitcoin.Psbt.fromBase64(req.body.psbt);
  // BUG: no call to validateFeeOutputs()
  // Buyer can submit a completed PSBT that omits platform fee and royalty
  psbt.finalizeAllInputs();
  const tx = psbt.extractTransaction();
  await broadcastTransaction(tx.toHex());
  res.json({ txid: tx.getId() });
});
```

### Secure: Platform co-signs to enforce fee structure

```typescript
app.post("/api/submit-psbt", async (req, res) => {
  const psbt = bitcoin.Psbt.fromBase64(req.body.psbt);
  const listing = await prisma.listing.findUnique({ where: { id: req.body.listingId } });

  // 1. Validate fee outputs on EVERY submission path
  if (!validateFeeOutputs(psbt, listing!)) {
    return res.status(400).json({ error: "Missing or insufficient platform fee/royalty" });
  }

  // 2. Platform co-signs to prove fee validation occurred
  // Without platform signature, TX is incomplete
  psbt.signInput(psbt.inputCount - 1, platformKeyPair); // platform's escrow input

  psbt.finalizeAllInputs();
  const tx = psbt.extractTransaction();
  await broadcastTransaction(tx.toHex());
  res.json({ txid: tx.getId() });
});
```

---

## 0x000c — Platform injects additional seller inputs

### Vulnerable: Server-side PSBT builder adds seller UTXOs beyond listing

```typescript
// VULNERABLE — server adds extra seller inputs for "fee coverage"
async function buildPurchasePsbt(listingId: string, buyerUtxos: UTXO[]) {
  const listing = await prisma.listing.findUnique({ where: { id: listingId } });
  const psbt = bitcoin.Psbt.fromBase64(listing!.signedPsbt);

  // Server adds the seller's OTHER UTXOs as "fee coverage"
  // Signing UI only shows input[0] (the listing), hiding injected inputs
  const sellerExtraUtxos = await fetchUtxos(listing!.sellerAddress);
  for (const utxo of sellerExtraUtxos.slice(0, 3)) {
    psbt.addInput({
      hash: utxo.txid,
      index: utxo.vout,
      witnessUtxo: { script: Buffer.from(utxo.scriptPubKey, "hex"), value: utxo.value },
    });
    // If seller used SIGHASH_ANYONECANPAY, their signature only covers input[0]
    // These extra inputs need separate signatures — but if the seller's wallet
    // auto-signs all inputs from the same key, the platform steals extra UTXOs
  }

  // Add buyer inputs...
  return psbt.toBase64();
}
```

### Secure: Client verifies exact input set before signing

```typescript
function verifyPsbtInputs(psbt: bitcoin.Psbt, expectedInputs: ExpectedInput[]): void {
  if (psbt.inputCount !== expectedInputs.length) {
    throw new Error(
      `Expected ${expectedInputs.length} inputs, got ${psbt.inputCount}. ` +
        `Platform may have injected additional inputs.`
    );
  }

  for (let i = 0; i < psbt.inputCount; i++) {
    const txInput = psbt.txInputs[i];
    const expected = expectedInputs[i];
    const actualOutpoint = `${Buffer.from(txInput.hash).reverse().toString("hex")}:${txInput.index}`;

    if (actualOutpoint !== `${expected.txid}:${expected.vout}`) {
      throw new Error(`Input ${i}: expected ${expected.txid}:${expected.vout}, got ${actualOutpoint}`);
    }
  }
}
```

---

## 0x000d — Escrow with no timelock refund path

### Vulnerable: Single-key platform escrow, no timelock

```typescript
// VULNERABLE — platform holds sole custody, no refund path
async function createEscrowOutput(sellerAddress: string, buyerAddress: string, amount: number) {
  // Single Taproot key-path output controlled by platform
  const { output, address } = bitcoin.payments.p2tr({
    internalPubkey: toXOnly(platformPubkey), // platform has unilateral control!
    network: bitcoin.networks.bitcoin,
  });

  // No script tree with timelock refund
  // No multi-sig with buyer/seller
  // If platform disappears, funds are locked forever

  return { escrowAddress: address, escrowOutput: output };
}
```

### Secure: 2-of-3 multisig with timelock refund in Tapscript

```typescript
async function secureEscrowOutput(
  sellerPubkey: Buffer,
  buyerPubkey: Buffer,
  platformPubkey: Buffer,
  refundTimelock: number
) {
  // Script path 1: 2-of-3 multisig (any two parties can release)
  const multisigLeaf = bitcoin.script.compile([
    bitcoin.opcodes.OP_2,
    toXOnly(sellerPubkey),
    toXOnly(buyerPubkey),
    toXOnly(platformPubkey),
    bitcoin.opcodes.OP_3,
    bitcoin.opcodes.OP_CHECKMULTISIG,
  ]);

  // Script path 2: buyer refund after timelock
  const refundLeaf = bitcoin.script.compile([
    bitcoin.script.number.encode(refundTimelock),
    bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY,
    bitcoin.opcodes.OP_DROP,
    toXOnly(buyerPubkey),
    bitcoin.opcodes.OP_CHECKSIG,
  ]);

  const NUMS_POINT = Buffer.from(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0", "hex"
  );

  const scriptTree: bitcoin.Taptree = [{ output: multisigLeaf }, { output: refundLeaf }];

  const { output, address } = bitcoin.payments.p2tr({
    internalPubkey: NUMS_POINT, // unspendable — forces script-path
    scriptTree,
    network: bitcoin.networks.bitcoin,
  });

  return { escrowAddress: address, escrowOutput: output };
}
```

---

## 0x000e — Dust limit violations destroy inscriptions

### Vulnerable: Inscription delivery at sub-dust value

```typescript
// VULNERABLE — inscription output below dust threshold
async function buildInscriptionDelivery(
  psbt: bitcoin.Psbt,
  buyerAddress: string,
  inscriptionValue: number
) {
  // Inscription delivery at 200 sats — below 546 dust limit!
  // Standard nodes will reject this transaction
  psbt.addOutput({ address: buyerAddress, value: 200 });

  // Change calculation absorbs "dust" into fee
  const totalIn = psbt.data.inputs.reduce((s, i) => s + (i.witnessUtxo?.value ?? 0), 0);
  const totalOut = psbt.txOutputs.reduce((s, o) => s + o.value, 0);
  const change = totalIn - totalOut - 1000; // fee estimate

  if (change < 546) {
    // BUG: sub-dust change silently absorbed as extra miner fee
    // Inscription output might also be rejected by nodes
    console.log("Change below dust — absorbed as fee");
  } else {
    psbt.addOutput({ address: buyerAddress, value: change });
  }
}
```

### Secure: Enforce dust limits on all outputs

```typescript
const DUST_LIMIT = 546; // P2WPKH minimum relay amount
const INSCRIPTION_MIN_VALUE = 546; // standard inscription value

function validateOutputDust(psbt: bitcoin.Psbt): void {
  for (let i = 0; i < psbt.txOutputs.length; i++) {
    const output = psbt.txOutputs[i];
    if (output.value < DUST_LIMIT) {
      throw new Error(
        `Output ${i} (${output.value} sats) is below dust limit (${DUST_LIMIT}). ` +
          `Nodes will reject this transaction.`
      );
    }
  }
}
```

---

## 0x000f — Marketplace API exposes signed PSBTs to unauthorized parties

### Vulnerable: Unauthenticated API returns full PSBT data

```typescript
// VULNERABLE — signed PSBTs accessible without authentication
app.get("/api/v1/listings", async (req, res) => {
  const listings = await prisma.listing.findMany();
  res.json(
    listings.map((l) => ({
      id: l.id,
      price: l.price,
      inscriptionId: l.inscriptionId,
      psbt: l.signedPsbt, // full signed PSBT — anyone can complete the trade!
    }))
  );
});

// No rate limiting — bots can scrape all PSBTs
// No authentication — anonymous access
```

### Secure: Authenticated access with rate limiting

```typescript
app.get("/api/v1/listings", async (req, res) => {
  const listings = await prisma.listing.findMany();
  // Public listing data — NO PSBTs
  res.json(
    listings.map((l) => ({
      id: l.id,
      price: l.price,
      inscriptionId: l.inscriptionId,
      // PSBT not included — must be requested via authenticated endpoint
    }))
  );
});

// PSBT only available via authenticated, rate-limited endpoint
app.post("/api/v1/listings/:id/request-psbt",
  authMiddleware,
  rateLimit({ windowMs: 60000, max: 5 }),
  async (req, res) => {
    // ... commit-reveal flow (see 0x0009)
  }
);
```

---

## Quick Reference: Import Patterns to Flag

| Pattern | Risk | Checkpoint |
|---------|------|------------|
| `sighashType: 0x82` in listing | Output theft | 0x0000 |
| `prisma.listing.delete` without UTXO spend | Replay attack | 0x0001 |
| No `MAX_FEE_RATE` in buyer completion | Fee extraction | 0x0002 |
| `fetchUtxos` without inscription filtering | Inscription loss | 0x0003 |
| `sort((a,b) => a.value - b.value)` for padding | Inscription as padding | 0x0004 |
| Single `ORD_API` endpoint, no cross-reference | False state | 0x0005 |
| No `availableBalance` check for BRC-20 | Double spend | 0x0006 |
| Manual `Runestone` builder without tag ordering | Cenotaph burn | 0x0007 |
| `res.send(inscription.content)` without CSP | XSS | 0x0008 |
| `listing.signedPsbt` in public GET response | Snipping | 0x0009 |
| `nSequence = 0xFFFFFFFD` on trade TX | Sandwich attack | 0x000a |
| `validateFeeOutputs` not called on all paths | Fee bypass | 0x000b |
| `psbt.addInput` for extra seller UTXOs | Input theft | 0x000c |
| `p2tr({ internalPubkey: platformPubkey })` only | No refund | 0x000d |
| `output.value: 200` for inscription delivery | Dust rejection | 0x000e |
| `signedPsbt` in unauthenticated API response | PSBT leak | 0x000f |
