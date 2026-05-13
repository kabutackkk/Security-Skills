# TypeScript Vulnerable Patterns for LN dApp Audits

Real-world vulnerable TypeScript patterns for Lightning Network dApps using `bolt11`, `@lightningpolar/lnrpc`, `ln-service`, `lnurl-pay`, `@boltz/boltz-core`, and common swap/payment processor backends. Each section maps to a checkpoint.

---

## 0x0000 — Preimage revealed before HTLC irrevocably committed

### Vulnerable: Swap service reveals preimage at 0 confirmations

```typescript
// VULNERABLE — reveals preimage before on-chain HTLC is confirmed
import { createHash, randomBytes } from "crypto";

class SubmarineSwapService {
  async onSwapPaymentReceived(swapId: string, htlcTx: BitcoinTx) {
    const swap = await db.getSwap(swapId);

    // BUG: accepts 0-confirmation HTLC as valid
    // The on-chain TX could be double-spent / RBF-replaced
    if (htlcTx.confirmations >= 0) {
      // Settles the LN invoice — reveals the preimage!
      await lnd.settleInvoice({ preimage: swap.preimage });

      // If on-chain HTLC is then double-spent, the service
      // has revealed the preimage but gets no on-chain payment
      // User gets the LN payment (via preimage) AND keeps their BTC
    }
  }
}
```

### Secure: Wait for sufficient confirmations

```typescript
class SecureSwapService {
  private readonly MIN_CONFIRMATIONS = 3; // for amounts < 1 BTC
  private readonly HIGH_VALUE_CONFIRMATIONS = 6; // for amounts >= 1 BTC

  async onSwapPaymentReceived(swapId: string, htlcTx: BitcoinTx) {
    const swap = await db.getSwap(swapId);
    const requiredConfs = swap.amount >= 100_000_000
      ? this.HIGH_VALUE_CONFIRMATIONS
      : this.MIN_CONFIRMATIONS;

    if (htlcTx.confirmations < requiredConfs) {
      console.log(`Swap ${swapId}: ${htlcTx.confirmations}/${requiredConfs} confirmations — waiting`);
      return; // do NOT reveal preimage yet
    }

    // Safe to settle
    await lnd.settleInvoice({ preimage: swap.preimage });
  }
}
```

---

## 0x0001 — Insecure preimage generation / preimage reuse

### Vulnerable: Math.random for preimage, reuse across swaps

```typescript
// VULNERABLE — predictable preimage generation
class InvoiceManager {
  generatePreimage(): Buffer {
    // BUG: Math.random is NOT cryptographically secure
    // Preimage can be predicted by observing pattern
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
    return Buffer.from(bytes);
  }

  // Also vulnerable: reusing preimage across payment hash and swap hash
  async createSubmarineSwapInvoice(swapId: string) {
    const preimage = this.generatePreimage();
    const paymentHash = createHash("sha256").update(preimage).digest();

    // Same preimage used for BOTH the LN invoice AND the on-chain HTLC
    // If the on-chain script uses a different hash, link is broken
    const invoice = await lnd.addInvoice({
      r_preimage: preimage,
      value: swapAmount,
    });

    // Store for later settlement
    await db.saveSwap(swapId, { preimage, paymentHash, invoice: invoice.payment_request });
  }
}
```

### Secure: CSPRNG preimage with uniqueness enforcement

```typescript
class SecureInvoiceManager {
  private usedPreimages = new Set<string>();

  generatePreimage(): Buffer {
    const preimage = randomBytes(32); // crypto.randomBytes — CSPRNG
    const hash = createHash("sha256").update(preimage).digest("hex");

    // Ensure uniqueness
    if (this.usedPreimages.has(hash)) {
      throw new Error("Preimage collision — regenerating");
    }
    this.usedPreimages.add(hash);

    return preimage;
  }
}
```

---

## 0x0002 — Payment secret not verified on HTLC acceptance

### Vulnerable: Accepts HTLCs without payment_secret validation

```typescript
// VULNERABLE — no payment_secret check, accepts legacy probing
import { subscribeToHtlcs } from "ln-service";

function setupHtlcHandler(lnd: any) {
  const sub = subscribeToHtlcAttempts({ lnd });

  sub.on("forward", async (htlc: any) => {
    // BUG: no payment_secret validation
    // Legacy invoices without payment_secret can be probed
    // An intermediary node can detect if the next hop is the final destination
    // by sending an HTLC with the correct payment_hash but wrong/missing secret

    if (htlc.is_receive && htlc.mtokens > 0) {
      // Accepts the HTLC without verifying payment_secret
      // This enables payment probing attacks
      await settleHtlc(htlc);
    }
  });
}
```

### Secure: Require and verify payment_secret (BOLT 11 `s` field)

```typescript
function secureHtlcHandler(lnd: any) {
  const sub = subscribeToHtlcAttempts({ lnd });

  sub.on("forward", async (htlc: any) => {
    if (htlc.is_receive) {
      const invoice = await db.getInvoiceByHash(htlc.id);
      if (!invoice) return rejectHtlc(htlc, "unknown_payment_hash");

      // Verify payment_secret matches
      if (!htlc.payment_secret || htlc.payment_secret !== invoice.payment_secret) {
        return rejectHtlc(htlc, "incorrect_payment_details");
      }

      await settleHtlc(htlc);
    }
  });
}
```

---

## 0x0003 — CLTV expiry delta too small

### Vulnerable: 6-block cltv_expiry_delta (minimum safe is 34+)

```typescript
// VULNERABLE — cltv_expiry_delta = 6 blocks (~1 hour)
const CHANNEL_CONFIG = {
  cltv_expiry_delta: 6, // WAY too small
  // If a force-close takes > 6 blocks to confirm, the incoming HTLC
  // expires before the outgoing HTLC can be claimed on-chain
  // Result: intermediary loses funds
};

// Also used in swap timelock calculation
async function createSwapInvoice(amountSats: number) {
  const invoice = await lnd.addInvoice({
    value: amountSats,
    cltv_expiry: 6, // user-facing invoice with 6-block CLTV
    // In fee spikes, this gives zero margin for on-chain settlement
  });
  return invoice;
}
```

### Secure: 40+ block delta with safety budget

```typescript
// BOLT-02 recommendation: cltv_expiry_delta >= 34 blocks
// Add buffer for fee spikes and confirmation delays
const SAFE_CLTV_DELTA = 40; // ~6.7 hours
const HIGH_VALUE_CLTV_DELTA = 80; // ~13.3 hours for large payments

function calculateCltvDelta(amountSats: number): number {
  if (amountSats > 1_000_000) return HIGH_VALUE_CLTV_DELTA;
  return SAFE_CLTV_DELTA;
}
```

---

## 0x0004 — CLTV value crosses block-height / timestamp boundary

### Vulnerable: Unbounded CLTV addition overflows into timestamp domain

```typescript
// VULNERABLE — CLTV arithmetic can cross 500M boundary
function computeCltvExpiry(currentBlockHeight: number, delta: number): number {
  const expiry = currentBlockHeight + delta;
  // BUG: no check for 500M boundary
  // If currentBlockHeight + delta >= 500_000_000, Bitcoin interprets
  // the value as a Unix timestamp instead of a block height
  // This effectively makes the HTLC unclaimable until that timestamp
  return expiry;
}

// Edge case: malicious peer sends cltv_expiry_delta = 499_000_000
// Resulting CLTV: currentHeight + 499M > 500M → timestamp domain
```

### Secure: Validate CLTV stays in block-height domain

```typescript
const MAX_BLOCK_HEIGHT = 499_999_999; // below timestamp threshold

function safeComputeCltvExpiry(currentBlockHeight: number, delta: number): number {
  const expiry = currentBlockHeight + delta;

  if (expiry >= 500_000_000) {
    throw new Error(
      `CLTV expiry ${expiry} crosses into timestamp domain (>= 500M). ` +
        `Delta ${delta} is too large.`
    );
  }

  if (delta > 100_000) {
    throw new Error(`CLTV delta ${delta} is unreasonably large`);
  }

  return expiry;
}
```

---

## 0x0005 — HTLC state orphaned before commitment_signed exchange

### Vulnerable: DB marks HTLC fulfilled before wire protocol completes

```typescript
// VULNERABLE — state update not bound to commitment exchange
class ChannelStateManager {
  async fulfillHtlc(channelId: string, htlcId: number, preimage: Buffer) {
    // Mark as fulfilled in DB BEFORE sending commitment_signed
    await db.updateHtlc(channelId, htlcId, {
      state: "FULFILLED",
      preimage: preimage.toString("hex"),
    });

    // If the process crashes HERE, the HTLC is marked fulfilled in DB
    // but the peer never received commitment_signed
    // The HTLC is orphaned — not settled on-chain or off-chain

    try {
      await lnd.sendCommitmentSigned(channelId);
      await lnd.waitForRevokeAndAck(channelId);
    } catch (error) {
      // DB says fulfilled, wire protocol says pending
      // Inconsistent state — potential fund loss
      console.error("Failed to exchange commitment:", error);
    }
  }
}
```

### Secure: State transitions bound to commitment exchange

```typescript
class SecureChannelStateManager {
  async fulfillHtlc(channelId: string, htlcId: number, preimage: Buffer) {
    // 1. Mark as SETTLING (not fulfilled yet)
    await db.updateHtlc(channelId, htlcId, { state: "SETTLING" });

    // 2. Complete the wire protocol
    await lnd.sendUpdateFulfillHtlc(channelId, htlcId, preimage);
    await lnd.sendCommitmentSigned(channelId);
    const revokeAck = await lnd.waitForRevokeAndAck(channelId);

    // 3. Only now mark as fulfilled — after commitment is irrevocable
    await db.updateHtlc(channelId, htlcId, {
      state: "FULFILLED",
      preimage: preimage.toString("hex"),
      commitmentHeight: revokeAck.commitmentNumber,
    });
  }
}
```

---

## 0x0006 — On-chain preimage not propagated to settle LN HTLCs

### Vulnerable: On-chain claim detected but LN side not settled

```typescript
// VULNERABLE — sees preimage on-chain but doesn't settle LN invoice
class ChainMonitor {
  async onTransactionConfirmed(tx: BitcoinTx) {
    // Check if this TX reveals a preimage (spending an HTLC output)
    for (const input of tx.vin) {
      const witness = input.txinwitness;
      if (witness && witness.length >= 3) {
        const possiblePreimage = Buffer.from(witness[1], "hex");
        const hash = createHash("sha256").update(possiblePreimage).digest("hex");

        const pendingSwap = await db.getSwapByHash(hash);
        if (pendingSwap) {
          // Found preimage on-chain! But...
          await db.markSwapClaimed(pendingSwap.id, possiblePreimage.toString("hex"));
          // BUG: doesn't use this preimage to settle the corresponding LN HTLC
          // If this was a forwarded payment, the incoming HTLC times out
          // and the node loses the payment amount
        }
      }
    }
  }
}
```

### Secure: Propagate preimage to all pending HTLCs

```typescript
class SecureChainMonitor {
  async onPreimageDetected(preimage: Buffer) {
    const hash = createHash("sha256").update(preimage).digest("hex");

    // 1. Settle any pending LN invoices with this hash
    const pendingInvoices = await db.getPendingInvoicesByHash(hash);
    for (const invoice of pendingInvoices) {
      await lnd.settleInvoice({ preimage });
    }

    // 2. Settle any pending incoming HTLCs on other channels
    const pendingHtlcs = await db.getPendingHtlcsByHash(hash);
    for (const htlc of pendingHtlcs) {
      await lnd.settleHtlc(htlc.channelId, htlc.htlcId, preimage);
    }

    // 3. Mark swap as complete
    await db.markSwapClaimed(hash, preimage.toString("hex"));
  }
}
```

---

## 0x0007 — Submarine swap refund timeout < LN invoice expiry

### Vulnerable: On-chain refund available before LN invoice expires

```typescript
// VULNERABLE — refund timeout is shorter than invoice expiry
const SWAP_CONFIG = {
  onChainHtlcTimelock: 144, // blocks (~1 day)
  lnInvoiceExpiry: 86400 * 2, // 2 days in seconds
  // BUG: user can wait for on-chain refund (1 day), then also claim LN payment
  // if the swap service settled the invoice before the refund was claimed
};

async function createSubmarineSwap(amountSats: number) {
  const preimage = randomBytes(32);
  const paymentHash = createHash("sha256").update(preimage).digest("hex");

  // LN invoice with 2-day expiry
  const invoice = await lnd.addInvoice({
    value: amountSats,
    expiry: SWAP_CONFIG.lnInvoiceExpiry,
    r_preimage: preimage,
  });

  // On-chain HTLC with 1-day refund timeout
  const htlcScript = buildHtlcScript(paymentHash, SWAP_CONFIG.onChainHtlcTimelock);
  // Refund available at block 144 — but invoice valid for 2 more days
  // This breaks atomicity
}
```

### Secure: Refund timeout > LN invoice expiry + safety margin

```typescript
const SAFE_SWAP_CONFIG = {
  lnInvoiceExpiry: 3600, // 1 hour
  onChainHtlcTimelock: 288, // ~2 days — much longer than invoice expiry
  // On-chain refund only available AFTER invoice has definitely expired
  // Plus safety margin for confirmation delays
};
```

---

## 0x0008 — Reverse swap timelock race condition

### Vulnerable: Service refund timeout equals user claim timeout

```typescript
// VULNERABLE — service and user have same timeout → race condition
async function createReverseSwap(amountSats: number) {
  const preimage = randomBytes(32);
  const paymentHash = createHash("sha256").update(preimage).digest("hex");

  const serviceRefundTimeout = 144; // blocks
  const userClaimTimeout = 144;     // same! race condition

  // Build on-chain HTLC
  const htlcScript = `
    OP_IF
      OP_SHA256 ${paymentHash} OP_EQUALVERIFY ${userPubkey} OP_CHECKSIG  // user claim (preimage)
    OP_ELSE
      ${serviceRefundTimeout} OP_CHECKLOCKTIMEVERIFY OP_DROP ${servicePubkey} OP_CHECKSIG  // service refund
    OP_ENDIF
  `;

  // At block 144: BOTH service refund AND user claim are valid
  // Service can front-run user's claim TX with their refund TX
  // User paid LN invoice but can't claim on-chain output
}
```

### Secure: User claim window before service refund becomes valid

```typescript
async function secureReverseSwap(amountSats: number) {
  const userClaimWindow = 72; // blocks — user has 72 blocks to claim after preimage reveal
  const serviceRefundTimeout = 288; // blocks — service can only refund after 288 blocks
  // Margin: 288 - 72 = 216 blocks (~36 hours) of safety

  // User has a guaranteed window to claim using the preimage
  // before the service's refund path becomes available
}
```

---

## 0x0009 — No force-close fee budget

### Vulnerable: Channel with no UTXO reserve for fee bumping

```typescript
// VULNERABLE — no anchor output support, no fee reserve
class ChannelManager {
  async openChannel(peerPubkey: string, capacitySats: number) {
    const channel = await lnd.openChannel({
      node_pubkey: peerPubkey,
      local_funding_amount: capacitySats,
      // No anchor channels — commitment TX fee is locked at open time
      // If fee market spikes 10x, force-close TX won't confirm in time
      private: false,
    });

    // No UTXO reserved for CPFP fee bumping
    // All wallet UTXOs could be used for payments, leaving nothing for emergency
    return channel;
  }

  async forceClose(channelPoint: string) {
    // If mempool is congested, this TX may not confirm before HTLC timeout
    // No ability to fee-bump → HTLC times out → counterparty claims funds
    await lnd.closeChannel({ channel_point: channelPoint, force: true });
  }
}
```

### Secure: Anchor channels + UTXO reserve

```typescript
class SecureChannelManager {
  private readonly FEE_RESERVE_SATS = 100_000; // reserve for fee bumping

  async openChannel(peerPubkey: string, capacitySats: number) {
    // Verify fee reserve exists
    const walletBalance = await lnd.getWalletBalance();
    if (walletBalance.confirmed_balance < this.FEE_RESERVE_SATS) {
      throw new Error(`Insufficient fee reserve: need ${this.FEE_RESERVE_SATS} sats for force-close safety`);
    }

    const channel = await lnd.openChannel({
      node_pubkey: peerPubkey,
      local_funding_amount: capacitySats,
      commitment_type: "ANCHORS", // anchor outputs for CPFP fee bumping
    });
    return channel;
  }
}
```

---

## 0x000a — No replacement cycling defense

### Vulnerable: No mempool monitoring or re-broadcast

```typescript
// VULNERABLE — no defense against replacement cycling attacks
const MEMPOOL_CONFIG = {
  monitorMempool: false,       // doesn't watch for conflicting TXs
  rebroadcastInterval: 0,     // never re-broadcasts
  feeEscalation: false,       // no automatic fee bumping
  pinningSizeLimit: Infinity,  // no pinning detection
};

async function claimHtlcOutput(htlcOutpoint: UTXO, preimage: Buffer) {
  const claimTx = buildClaimTx(htlcOutpoint, preimage);
  await broadcastTransaction(claimTx.toHex());
  // If attacker replaces this TX via cycling attack, we never re-broadcast
  // The HTLC times out and attacker claims via timeout path
}
```

### Secure: Active mempool monitoring + automatic re-broadcast

```typescript
class AntiCyclingDefense {
  async claimHtlcWithDefense(htlcOutpoint: UTXO, preimage: Buffer) {
    const claimTx = buildClaimTx(htlcOutpoint, preimage);
    const txid = await broadcastTransaction(claimTx.toHex());

    // Monitor for replacement/eviction
    const monitor = setInterval(async () => {
      const status = await getMempoolStatus(txid);
      if (status === "evicted" || status === "replaced") {
        // Re-broadcast with higher fee
        const bumpedTx = buildClaimTx(htlcOutpoint, preimage, { feeMultiplier: 1.5 });
        await broadcastTransaction(bumpedTx.toHex());
      }
    }, 10_000); // check every 10 seconds

    // Clean up after confirmation
    const confirmed = await waitForConfirmation(txid);
    clearInterval(monitor);
  }
}
```

---

## 0x000b — Settlement treated as final at 1 confirmation

### Vulnerable: Marks payment complete at 1 conf, no reorg handling

```typescript
// VULNERABLE — 1 confirmation = final, no reorg protection
class SettlementTracker {
  async onBlockConnected(block: BitcoinBlock) {
    for (const tx of block.transactions) {
      const pendingSwap = await db.getSwapByTxid(tx.txid);
      if (pendingSwap && pendingSwap.confirmations >= 1) {
        // BUG: 1 confirmation treated as final
        await db.markSwapComplete(pendingSwap.id);
        await creditUserBalance(pendingSwap.userId, pendingSwap.amount);
        // If this block is reorged, user has been credited but TX is gone
      }
    }
  }

  async onBlockDisconnected(block: BitcoinBlock) {
    // BUG: no reorg handling — state not rolled back
    console.log("Block disconnected — ignoring");
  }
}
```

### Secure: Require 3+ confirmations + reorg rollback

```typescript
class SecureSettlementTracker {
  private readonly MIN_CONFIRMATIONS = 3;

  async onBlockDisconnected(block: BitcoinBlock) {
    // Roll back any settlements from this block
    const affectedSwaps = await db.getSwapsByBlockHash(block.hash);
    for (const swap of affectedSwaps) {
      await db.markSwapPending(swap.id);
      await debitUserBalance(swap.userId, swap.amount);
      console.warn(`Reorg detected — rolled back swap ${swap.id}`);
    }
  }
}
```

---

## 0x000c — Watchtower with full signing keys, single instance

### Vulnerable: Single watchtower receives full private keys

```typescript
// VULNERABLE — single watchtower, full keys, volatile storage
class WatchtowerClient {
  async delegateChannel(channelId: string) {
    // BUG: sends full signing keys to watchtower
    const channelKey = await lnd.exportChannelKey(channelId);

    await fetch(`${WATCHTOWER_URL}/delegate`, {
      method: "POST",
      body: JSON.stringify({
        channelId,
        privateKey: channelKey.toString("hex"), // full private key!
        // Watchtower can now spend channel funds unilaterally
      }),
    });
    // Single watchtower — if it goes offline, no breach detection
    // Volatile memory storage — data lost on restart
  }
}
```

### Secure: Multiple watchtowers with breach hints only

```typescript
class SecureWatchtowerClient {
  private watchtowers = [
    "https://watchtower-1.example.com",
    "https://watchtower-2.example.com",
    "https://watchtower-3.example.com",
  ];

  async delegateChannel(channelId: string, revokedState: RevokedState) {
    // Only send breach hint (hash of revoked commitment) + pre-signed penalty TX
    // NOT the private key
    const breachHint = createHash("sha256")
      .update(revokedState.commitmentTxid)
      .digest("hex")
      .slice(0, 32);

    const penaltyTx = buildPenaltyTx(revokedState); // pre-signed

    // Distribute to ALL watchtowers
    await Promise.all(
      this.watchtowers.map((wt) =>
        fetch(`${wt}/delegate`, {
          method: "POST",
          body: JSON.stringify({ breachHint, penaltyTx: penaltyTx.toHex() }),
        })
      )
    );
  }
}
```

---

## 0x000d — Revocation secrets in volatile memory only

### Vulnerable: In-memory revocation store with no persistence

```typescript
// VULNERABLE — revocation secrets lost on crash
class RevocationStore {
  private secrets = new Map<string, Buffer>(); // in-memory only!

  store(commitmentNumber: number, secret: Buffer) {
    this.secrets.set(commitmentNumber.toString(), secret);
    // No fsync, no durable storage
    // If process crashes, all revocation secrets are lost
    // Old (revoked) states can be broadcast without penalty
  }

  // Also vulnerable: wrong key derivation in penalty TX
  buildPenaltyTx(revokedCommitment: any): bitcoin.Transaction {
    const secret = this.secrets.get(revokedCommitment.number.toString());
    if (!secret) throw new Error("Revocation secret not found");

    // BUG: derives penalty key from per_commitment_point incorrectly
    // Wrong formula: should be revocation_basepoint * SHA256(per_commitment_point || revocation_basepoint)
    const penaltyKey = createHash("sha256")
      .update(secret) // wrong — should include per_commitment_point
      .digest();

    return buildPenaltyTransaction(revokedCommitment, penaltyKey);
  }
}
```

### Secure: Durable storage with fsync before revoke_and_ack

```typescript
import { writeFileSync, fdatasyncSync, openSync, closeSync } from "fs";

class DurableRevocationStore {
  private dbPath: string;

  store(commitmentNumber: number, secret: Buffer) {
    // Write to durable storage BEFORE sending revoke_and_ack
    const entry = `${commitmentNumber}:${secret.toString("hex")}\n`;
    const fd = openSync(this.dbPath, "a");
    writeFileSync(fd, entry);
    fdatasyncSync(fd); // force flush to disk
    closeSync(fd);
    // Only after fsync completes is it safe to send revoke_and_ack
  }
}
```

---

## 0x000e — Client-side keys in plaintext localStorage

### Vulnerable: Preimages and keys stored unencrypted in browser

```typescript
// VULNERABLE — plaintext localStorage, no CSP, third-party script access
class WalletStorage {
  savePreimage(paymentHash: string, preimage: string) {
    localStorage.setItem(`preimage:${paymentHash}`, preimage);
    // Plaintext — any XSS or third-party script can read it
  }

  saveNodeKey(key: string) {
    localStorage.setItem("node_private_key", key);
    // Private key in plaintext localStorage!
    // Any script on the page can steal it
  }

  getNodeKey(): string {
    return localStorage.getItem("node_private_key") ?? "";
  }
}

// No Content-Security-Policy headers
// Third-party analytics/ad scripts have full localStorage access
```

### Secure: Encrypted storage with CSP

```typescript
class SecureWalletStorage {
  private encryptionKey: CryptoKey;

  async init(password: string) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits", "deriveKey"]
    );
    this.encryptionKey = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async savePreimage(paymentHash: string, preimage: string) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      this.encryptionKey,
      new TextEncoder().encode(preimage)
    );
    localStorage.setItem(
      `preimage:${paymentHash}`,
      JSON.stringify({ iv: Array.from(iv), data: Array.from(new Uint8Array(encrypted)) })
    );
  }
}

// Server must also set: Content-Security-Policy: script-src 'self'; object-src 'none'
```

---

## 0x000f — Taproot channel key-path bypasses CSV delay

### Vulnerable: Single-party internal key, no NUMS, no CSV on key-path

```typescript
// VULNERABLE — Taproot channel with key-path bypass
function buildTaprootChannelOutput(localPubkey: Buffer, remotePubkey: Buffer) {
  // Script path: CSV-delayed local output
  const localDelayedLeaf = bitcoin.script.compile([
    bitcoin.script.number.encode(144), // to_self_delay
    bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY,
    bitcoin.opcodes.OP_DROP,
    toXOnly(localPubkey),
    bitcoin.opcodes.OP_CHECKSIG,
  ]);

  // BUG: local party's real key as internal key
  // Can spend via key-path immediately — bypasses CSV delay
  // Remote party's revocation mechanism is useless
  return bitcoin.payments.p2tr({
    internalPubkey: toXOnly(localPubkey), // should be MuSig2(local, remote) or NUMS
    scriptTree: { output: localDelayedLeaf },
  });
}
```

### Secure: MuSig2 aggregate key or NUMS for internal key

```typescript
function secureTaprootChannel(localPubkey: Buffer, remotePubkey: Buffer) {
  // Internal key: MuSig2 aggregate of both parties
  // Cooperative close: both sign key-path (instant, cheap)
  // Unilateral close: script-path with CSV delay (as designed)
  const aggregateKey = musig2KeyAgg([localPubkey, remotePubkey]);

  const localDelayedLeaf = bitcoin.script.compile([
    bitcoin.script.number.encode(144),
    bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY,
    bitcoin.opcodes.OP_DROP,
    toXOnly(localPubkey),
    bitcoin.opcodes.OP_CHECKSIG,
  ]);

  const remoteImmediateLeaf = bitcoin.script.compile([
    toXOnly(remotePubkey),
    bitcoin.opcodes.OP_CHECKSIG,
  ]);

  return bitcoin.payments.p2tr({
    internalPubkey: toXOnly(aggregateKey), // both parties needed for key-path
    scriptTree: [{ output: localDelayedLeaf }, { output: remoteImmediateLeaf }],
  });
}
```

---

## 0x0010 — PTLC adaptor signature nonce reuse / secret malleability

### Vulnerable: Static nonce in adaptor signature, no verification

```typescript
// VULNERABLE — deterministic nonce for PTLC adaptor signatures
class PTLCManager {
  generateNonce(privateKey: Buffer, message: Buffer): Buffer {
    // BUG: deterministic nonce — same (key, message) pair = same nonce
    // If attacker can influence the message, they can force nonce reuse
    return createHmac("sha256", privateKey).update(message).digest();
  }

  createAdaptorSignature(privateKey: Buffer, adaptorPoint: Buffer, message: Buffer) {
    const nonce = this.generateNonce(privateKey, message);
    // Nonce reuse across different adaptor points → private key extraction

    // Also BUG: no verification of adaptor signature
    const adaptorSig = schnorrAdaptorSign(privateKey, nonce, adaptorPoint, message);
    return adaptorSig;
  }

  extractSecret(adaptorSig: Buffer, completeSig: Buffer): Buffer {
    // BUG: no check for secret malleability
    // Attacker can provide a complete signature that reveals a different
    // secret than expected (negated secret)
    return Buffer.from(
      bigintXor(BigInt("0x" + completeSig.toString("hex")), BigInt("0x" + adaptorSig.toString("hex")))
        .toString(16)
        .padStart(64, "0"),
      "hex"
    );
  }
}
```

### Secure: Random nonce + adaptor verification + malleability check

```typescript
class SecurePTLCManager {
  createAdaptorSignature(privateKey: Buffer, adaptorPoint: Buffer, message: Buffer) {
    // Fresh CSPRNG nonce
    const nonce = randomBytes(32);

    const adaptorSig = schnorrAdaptorSign(privateKey, nonce, adaptorPoint, message);

    // Verify the adaptor signature is valid
    const pubkey = ecc.pointFromScalar(privateKey);
    if (!schnorrAdaptorVerify(adaptorSig, pubkey!, adaptorPoint, message)) {
      throw new Error("Self-verification of adaptor signature failed");
    }

    // Securely erase nonce
    nonce.fill(0);
    return adaptorSig;
  }

  extractSecret(adaptorSig: Buffer, completeSig: Buffer, expectedPoint: Buffer): Buffer {
    const secret = schnorrExtractAdaptorSecret(adaptorSig, completeSig);

    // Verify extracted secret matches expected point (anti-malleability)
    const derivedPoint = ecc.pointFromScalar(secret);
    if (!derivedPoint || !Buffer.from(derivedPoint).equals(expectedPoint)) {
      throw new Error("Extracted secret does not match expected adaptor point — possible malleability");
    }

    return secret;
  }
}
```

---

## Quick Reference: Import Patterns to Flag

| Pattern | Risk | Checkpoint |
|---------|------|------------|
| `settleInvoice` at 0 confirmations | Preimage theft | 0x0000 |
| `Math.random()` for preimage bytes | Predictable preimage | 0x0001 |
| No `payment_secret` check on HTLC | Payment probing | 0x0002 |
| `cltv_expiry_delta: 6` | Timeout race loss | 0x0003 |
| No 500M CLTV boundary check | Timestamp domain overflow | 0x0004 |
| DB update before `commitment_signed` | Orphaned HTLC state | 0x0005 |
| Preimage detected on-chain but not settled on LN | Lost forwarded payment | 0x0006 |
| `onChainHtlcTimelock < lnInvoiceExpiry` | Double claim | 0x0007 |
| `serviceRefundTimeout === userClaimTimeout` | Timelock race | 0x0008 |
| No anchor channels, no fee reserve | Unconfirmable force-close | 0x0009 |
| `monitorMempool: false`, no re-broadcast | Replacement cycling | 0x000a |
| `confirmations >= 1` as final | Reorg vulnerability | 0x000b |
| `privateKey` sent to single watchtower | Custody compromise | 0x000c |
| In-memory `Map` for revocation secrets | Secrets lost on crash | 0x000d |
| `localStorage.setItem("node_private_key")` | XSS key theft | 0x000e |
| `internalPubkey: toXOnly(localPubkey)` in channel | CSV bypass | 0x000f |
| Deterministic nonce for adaptor signatures | Key extraction | 0x0010 |
