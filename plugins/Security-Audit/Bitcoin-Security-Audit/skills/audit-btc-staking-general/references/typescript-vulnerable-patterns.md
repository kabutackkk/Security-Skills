# TypeScript Vulnerable Patterns for BTC Staking Audits

Real-world vulnerable TypeScript patterns for Babylon-style BTC staking using `bitcoinjs-lib`, `@babylonlabs-io/btc-staking-ts`, `@scure/btc-signer`, and `tiny-secp256k1`. Each section maps to a checkpoint.

---

## 0x0000 — Covenant uses trusted third party instead of cryptographic enforcement

### Vulnerable: Staking output uses validator's real key as Taproot internal key

```typescript
// VULNERABLE — validator can bypass covenant via key-path spend
import * as bitcoin from "bitcoinjs-lib";
import { toXOnly } from "bitcoinjs-lib/src/psbt/bip371";
import * as ecc from "tiny-secp256k1";

bitcoin.initEccLib(ecc);

function createStakingOutput(
  stakerPubkey: Buffer,
  validatorPubkey: Buffer,
  covenantPubkeys: Buffer[],
  stakingTimelock: number
) {
  // Tapscript leaves for covenant enforcement
  const unbondingLeaf = buildUnbondingScript(stakerPubkey, validatorPubkey, covenantPubkeys);
  const slashingLeaf = buildSlashingScript(validatorPubkey, covenantPubkeys);
  const timelockLeaf = buildTimelockScript(stakerPubkey, stakingTimelock);

  const scriptTree: bitcoin.Taptree = [
    { output: unbondingLeaf },
    [{ output: slashingLeaf }, { output: timelockLeaf }],
  ];

  // BUG: validator's real pubkey as internal key — can spend via key-path!
  // Bypasses all Tapscript conditions (unbonding, slashing, timelock)
  const { output, address } = bitcoin.payments.p2tr({
    internalPubkey: toXOnly(validatorPubkey), // should be NUMS point
    scriptTree,
    network: bitcoin.networks.bitcoin,
  });

  return { stakingAddress: address, stakingOutput: output };
}
```

### Secure: NUMS internal key disables key-path spending

```typescript
// BIP-341 unspendable point — no known discrete log
const NUMS_KEY = Buffer.from(
  "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0", "hex"
);

function secureStakingOutput(
  stakerPubkey: Buffer,
  validatorPubkey: Buffer,
  covenantPubkeys: Buffer[],
  stakingTimelock: number
) {
  const scriptTree = buildStakingScriptTree(stakerPubkey, validatorPubkey, covenantPubkeys, stakingTimelock);

  const { output, address } = bitcoin.payments.p2tr({
    internalPubkey: NUMS_KEY, // unspendable — forces script-path only
    scriptTree,
    network: bitcoin.networks.bitcoin,
  });

  return { stakingAddress: address, stakingOutput: output };
}
```

---

## 0x0001 — Pre-signed transaction set incomplete

### Vulnerable: Only unbonding TX pre-signed, missing slashing variants

```typescript
// VULNERABLE — incomplete pre-signed transaction set
interface StakingSession {
  stakingTx: bitcoin.Transaction;
  preSignedTxs: Map<string, bitcoin.Transaction>;
}

async function initializeStaking(
  stakerKeyPair: any,
  validatorPubkey: Buffer,
  amount: number
): Promise<StakingSession> {
  const stakingTx = buildStakingTransaction(stakerKeyPair, validatorPubkey, amount);

  const preSignedTxs = new Map<string, bitcoin.Transaction>();

  // Only pre-signs unbonding from active state
  const unbondingTx = buildUnbondingTransaction(stakingTx, stakerKeyPair, validatorPubkey);
  preSignedTxs.set("unbond_from_active", unbondingTx);

  // MISSING: slashing from active state
  // MISSING: slashing from unbonding state
  // MISSING: emergency recovery transaction
  // MISSING: timelock expiry transaction

  // Without slashing TXs pre-signed, equivocation cannot be punished
  // The protocol's economic security guarantee is broken

  return { stakingTx, preSignedTxs };
}
```

### Secure: Complete pre-signed set covering all state transitions

```typescript
async function secureInitializeStaking(
  stakerKeyPair: any,
  validatorPubkey: Buffer,
  covenantPubkeys: Buffer[],
  amount: number
): Promise<StakingSession> {
  const stakingTx = buildStakingTransaction(stakerKeyPair, validatorPubkey, amount);
  const preSignedTxs = new Map<string, bitcoin.Transaction>();

  // All state transitions must have pre-signed TXs:
  const txSet = [
    { name: "unbond_from_active", builder: buildUnbondingTx },
    { name: "slash_from_active", builder: buildSlashingFromActiveTx },
    { name: "slash_from_unbonding", builder: buildSlashingFromUnbondingTx },
    { name: "timelock_expiry", builder: buildTimelockExpiryTx },
    { name: "emergency_recovery", builder: buildEmergencyRecoveryTx },
    { name: "burn_on_unrecoverable_fault", builder: buildBurnTx },
  ];

  for (const { name, builder } of txSet) {
    const tx = builder(stakingTx, stakerKeyPair, validatorPubkey, covenantPubkeys);
    preSignedTxs.set(name, tx);
  }

  // Verify all TXs are valid and properly signed
  for (const [name, tx] of preSignedTxs) {
    if (!verifyPreSignedTx(tx, stakingTx)) {
      throw new Error(`Pre-signed TX '${name}' failed verification`);
    }
  }

  return { stakingTx, preSignedTxs };
}
```

---

## 0x0002 — Covenant key material not destroyed after pre-signing

### Vulnerable: HD wallet retains covenant key derivation capability

```typescript
// VULNERABLE — staker's covenant key is re-derivable from HD wallet
import BIP32Factory from "bip32";

class StakingWallet {
  private masterKey: any; // BIP-32 master key

  async createStake(validatorPubkey: Buffer, amount: number) {
    // Derive staking key from HD wallet
    const stakingKey = this.masterKey.derivePath("m/86'/0'/0'/2/0");
    // This key is used to pre-sign covenant transactions

    const stakingTx = buildStakingTransaction(stakingKey, validatorPubkey, amount);
    const preSignedTxs = preSignAllTransactions(stakingTx, stakingKey, validatorPubkey);

    // BUG: stakingKey is still derivable from masterKey
    // The staker can re-derive the key and create unauthorized spending TXs
    // that bypass covenant restrictions (if combined with validator cooperation)

    return { stakingTx, preSignedTxs };
    // stakingKey should be destroyed here but masterKey keeps it alive
  }
}
```

### Secure: Ephemeral key with secure destruction

```typescript
class SecureStakingWallet {
  async createStake(validatorPubkey: Buffer, amount: number) {
    // Generate an ephemeral key pair for this specific stake
    const stakingKeyBuffer = randomBytes(32);
    const stakingKey = ECPair.fromPrivateKey(stakingKeyBuffer);

    const stakingTx = buildStakingTransaction(stakingKey, validatorPubkey, amount);
    const preSignedTxs = preSignAllTransactions(stakingTx, stakingKey, validatorPubkey);

    // Securely destroy the private key after pre-signing
    stakingKeyBuffer.fill(0);
    // The only way to spend is through the pre-signed transactions

    return { stakingTx, preSignedTxs };
  }
}
```

---

## 0x0003 — EOTS false positive triggers slashing on non-equivocation

### Vulnerable: Equivocation detector doesn't verify messages differ

```typescript
// VULNERABLE — triggers slashing for any two sigs at same height
interface EOTSSignature {
  height: number;
  signature: Buffer;
  message: Buffer;
  publicKey: Buffer;
}

function detectEquivocation(
  sig1: EOTSSignature,
  sig2: EOTSSignature
): boolean {
  // BUG: only checks height match, not that messages differ
  if (sig1.height !== sig2.height) return false;
  if (!sig1.publicKey.equals(sig2.publicKey)) return false;

  // Should also check: sig1.message !== sig2.message
  // Without this, signing the SAME block twice (retry, network dupe)
  // falsely triggers slashing

  return true; // false positive!
}

// Also vulnerable: nonce binding excludes height
function generateEOTSNonce(privateKey: Buffer, message: Buffer): Buffer {
  // BUG: nonce doesn't include block height
  // Two messages at different heights could produce same nonce collision
  return createHmac("sha256", privateKey).update(message).digest();
}
```

### Secure: Verify messages differ + include height in nonce binding

```typescript
function secureDetectEquivocation(sig1: EOTSSignature, sig2: EOTSSignature): boolean {
  if (sig1.height !== sig2.height) return false;
  if (!sig1.publicKey.equals(sig2.publicKey)) return false;

  // MUST verify messages are actually different (not just duplicate delivery)
  if (sig1.message.equals(sig2.message)) {
    console.log("Same message signed twice at same height — NOT equivocation (retry/dupe)");
    return false;
  }

  // True equivocation: same key, same height, different messages
  return true;
}
```

---

## 0x0004 — Missing pre-signed slashing transaction

### Vulnerable: Slashing relies on real-time validator cooperation

```typescript
// VULNERABLE — slashing requires validator to sign at slash time
async function slashValidator(
  stakingUtxo: UTXO,
  equivocationProof: EquivocationProof,
  validatorPubkey: Buffer
) {
  // Build slashing TX at slash time — requires validator signature!
  const slashingPsbt = new bitcoin.Psbt({ network: bitcoin.networks.bitcoin });

  slashingPsbt.addInput({
    hash: stakingUtxo.txid,
    index: stakingUtxo.vout,
    witnessUtxo: { script: Buffer.from(stakingUtxo.scriptPubKey, "hex"), value: stakingUtxo.value },
  });

  // Burn output (slashing)
  slashingPsbt.addOutput({
    script: bitcoin.script.compile([bitcoin.opcodes.OP_RETURN]),
    value: 0,
  });

  // BUG: needs validator's signature at slash time
  // A rational validator will NEVER cooperate with their own slashing
  // The slashing TX should be PRE-SIGNED before staking begins

  return slashingPsbt.toBase64(); // useless without validator sig
}
```

### Secure: Pre-signed slashing TX created at stake initialization

```typescript
async function createPreSignedSlashingTx(
  stakingTx: bitcoin.Transaction,
  stakerKeyPair: any,
  validatorKeyPair: any,
  covenantPubkeys: Buffer[]
): Promise<bitcoin.Transaction> {
  const slashingPsbt = new bitcoin.Psbt({ network: bitcoin.networks.bitcoin });

  const stakingOutpoint = { txid: stakingTx.getId(), vout: 0 };
  slashingPsbt.addInput({
    hash: stakingOutpoint.txid,
    index: stakingOutpoint.vout,
    witnessUtxo: {
      script: stakingTx.outs[0].script,
      value: stakingTx.outs[0].value,
    },
    tapLeafScript: /* slashing leaf script */,
  });

  // Burn output
  slashingPsbt.addOutput({
    script: bitcoin.script.compile([bitcoin.opcodes.OP_RETURN]),
    value: 0,
  });

  // Validator signs NOW, before staking begins
  // This signature is stored and used IF equivocation occurs
  slashingPsbt.signInput(0, validatorKeyPair);
  // Staker also signs
  slashingPsbt.signInput(0, stakerKeyPair);
  // Covenant committee members sign
  for (const covenantKey of covenantKeyPairs) {
    slashingPsbt.signInput(0, covenantKey);
  }

  slashingPsbt.finalizeAllInputs();
  return slashingPsbt.extractTransaction();
}
```

---

## 0x0005 — Slashing triggered by non-equivocation events

```typescript
// VULNERABLE — slashes for inactivity and unverifiable evidence
async function processSlashingEvidence(evidence: SlashingEvidence) {
  switch (evidence.type) {
    case "equivocation":
      // Legitimate: two different blocks signed at same height
      await executeSlashing(evidence);
      break;
    case "inactivity":
      // BUG: inactivity is not a slashable offense in BTC staking
      // Validator might just be offline — burning their BTC is unjust
      await executeSlashing(evidence); // should NOT slash
      break;
    case "pos_chain_evidence":
      // BUG: PoS chain evidence cannot be verified on Bitcoin
      // A malicious PoS chain could fabricate evidence to steal BTC
      await executeSlashing(evidence); // unverifiable!
      break;
  }
}
```

### Secure: Only slash on cryptographically provable equivocation

```typescript
async function secureProcessEvidence(evidence: SlashingEvidence) {
  if (evidence.type !== "equivocation") {
    console.log(`Evidence type '${evidence.type}' is not slashable — only equivocation triggers slashing`);
    return;
  }

  // Verify equivocation is cryptographically provable
  const { sig1, sig2, publicKey, height } = evidence;

  // 1. Both signatures are valid
  if (!verifyEOTSSignature(sig1, publicKey) || !verifyEOTSSignature(sig2, publicKey)) {
    throw new Error("Invalid signatures in equivocation proof");
  }

  // 2. Same height, different messages
  if (sig1.height !== sig2.height || sig1.message.equals(sig2.message)) {
    throw new Error("Not a valid equivocation — same message or different height");
  }

  // 3. Extract private key (proves equivocation is real)
  const extractedKey = extractEOTSPrivateKey(sig1, sig2);
  if (!extractedKey) throw new Error("Failed to extract key — not true equivocation");

  await executeSlashing(evidence);
}
```

---

## 0x0006 — Unbonding timelock insufficient for slashing evidence

```typescript
// VULNERABLE — 50-block unbonding period, ~8 hours — too short
const UNBONDING_BLOCKS = 50; // should be 1008+ (1 week)
```

---

## 0x0007 — Timelock bypassed via Taproot key-path

```typescript
// VULNERABLE — timelock leaf exists but key-path bypasses it
function buildTimelockOutput(stakerPubkey: Buffer, validatorPubkey: Buffer, timelock: number) {
  const timelockLeaf = bitcoin.script.compile([
    bitcoin.script.number.encode(timelock),
    bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY,
    bitcoin.opcodes.OP_DROP,
    toXOnly(stakerPubkey),
    bitcoin.opcodes.OP_CHECKSIG,
  ]);

  // BUG 1: validator's real key as internal key — can bypass OP_CSV
  // BUG 2: unbonding leaf MISSING OP_CSV — no timelock enforcement
  const unbondingLeaf = bitcoin.script.compile([
    toXOnly(stakerPubkey),
    bitcoin.opcodes.OP_CHECKSIGVERIFY,
    toXOnly(validatorPubkey),
    bitcoin.opcodes.OP_CHECKSIG,
    // Missing: OP_CHECKSEQUENCEVERIFY for unbonding delay
  ]);

  return bitcoin.payments.p2tr({
    internalPubkey: toXOnly(validatorPubkey), // bypass!
    scriptTree: [{ output: timelockLeaf }, { output: unbondingLeaf }],
  });
}
```

---

## 0x0008 — Staking TX doesn't commit to exact unbonding outputs

```typescript
// VULNERABLE — staking TX outputs not committed in pre-signed TXs
async function buildStakingTx(stakerKeyPair: any, amount: number) {
  const psbt = new bitcoin.Psbt({ network: bitcoin.networks.bitcoin });
  // ... add inputs ...

  psbt.addOutput({
    address: stakingAddress,
    value: amount,
  });

  // BUG: burn address is a regular P2TR — not provably unburnable
  // Someone could have the key for this "burn" address
  psbt.addOutput({
    address: "bc1p" + "0".repeat(58), // looks like burn but isn't provably unburnable
    value: 0,
  });

  // BUG: fee in pre-signed TX is fixed at 10000 sats — doesn't track fee market
  // When fee market spikes, pre-signed TXs become unbroadcastable
  return psbt;
}
```

---

## 0x0009 — Validator key equals staking spending key

```typescript
// VULNERABLE — shared key material between validator role and spending authority
class StakingNode {
  private validatorKey: Buffer;

  constructor(seed: Buffer) {
    const masterKey = bip32.fromSeed(seed);
    // Same HD derivation for both validator signing and spending!
    this.validatorKey = masterKey.derivePath("m/86'/0'/0'/0/0").privateKey!;
  }

  signBlock(block: Block): Buffer {
    // Uses validatorKey for PoS block signing (EOTS)
    return eotsSign(this.validatorKey, block.hash);
  }

  spendStakingOutput(stakingUtxo: UTXO): bitcoin.Psbt {
    // Uses SAME key for spending — if EOTS key is extracted via equivocation,
    // attacker gets the spending key too!
    const psbt = new bitcoin.Psbt();
    psbt.addInput({ /* stakingUtxo */ });
    psbt.signInput(0, ECPair.fromPrivateKey(this.validatorKey));
    return psbt;
  }
}
```

### Secure: Separate key material

```typescript
class SecureStakingNode {
  private validatorEOTSKey: Buffer; // for PoS block signing only
  private stakingSpendKey: Buffer;  // for BTC spending only

  constructor(seed: Buffer) {
    const masterKey = bip32.fromSeed(seed);
    // Different derivation paths — key compromise is not transitive
    this.validatorEOTSKey = masterKey.derivePath("m/86'/0'/1'/0/0").privateKey!;
    this.stakingSpendKey = masterKey.derivePath("m/86'/0'/2'/0/0").privateKey!;
  }
}
```

---

## 0x000a — Key rotation invalidates existing slashing TXs

```typescript
// VULNERABLE — key rotation doesn't re-sign slashing TXs
async function rotateValidatorKey(validatorId: string, newPubkey: Buffer) {
  const validator = await db.getValidator(validatorId);

  // Update validator key in DB
  await db.updateValidator(validatorId, { pubkey: newPubkey });

  // BUG: existing pre-signed slashing TXs use the OLD key
  // They're now unenforceable — old key can no longer authorize slashing
  // No minimum rotation interval — can rotate every block
  // No overlap period where both keys are valid

  console.log(`Validator ${validatorId} rotated to new key`);
  // Active stakes are now effectively unslashable until re-registration
}
```

### Secure: Re-sign slashing TXs and enforce rotation interval

```typescript
async function secureRotateKey(validatorId: string, newPubkey: Buffer, newKeyPair: any) {
  const validator = await db.getValidator(validatorId);

  // 1. Minimum rotation interval
  const lastRotation = validator.lastKeyRotation;
  if (Date.now() - lastRotation < MIN_ROTATION_INTERVAL_MS) {
    throw new Error("Key rotation too frequent — minimum interval not met");
  }

  // 2. Re-sign ALL active slashing TXs with new key
  const activeStakes = await db.getActiveStakes(validatorId);
  for (const stake of activeStakes) {
    const newSlashingTx = await reSignSlashingTx(stake, newKeyPair);
    await db.updateSlashingTx(stake.id, newSlashingTx);
  }

  // 3. Update validator key
  await db.updateValidator(validatorId, {
    pubkey: newPubkey,
    lastKeyRotation: Date.now(),
  });
}
```

---

## 0x000b — Rewards depend on trusted oracle alone

```typescript
// VULNERABLE — single oracle, no proof, selective distribution possible
async function distributeRewards(epoch: number) {
  // Single trusted oracle reports rewards
  const rewards = await fetch(`${ORACLE_URL}/rewards/${epoch}`).then((r) => r.json());

  // No Merkle proof, no on-chain state root, no independent verification
  for (const { staker, amount } of rewards.distributions) {
    await sendReward(staker, amount);
  }
  // Oracle operator can selectively withhold or inflate rewards
}
```

### Secure: Merkle proof-based verifiable distribution

```typescript
async function verifiableDistributeRewards(epoch: number) {
  // Fetch reward data with Merkle proof
  const { root, distributions, proofs } = await fetchRewardData(epoch);

  // Verify root matches on-chain committed state
  const onChainRoot = await getOnChainRewardRoot(epoch);
  if (root !== onChainRoot) {
    throw new Error("Reward root mismatch — oracle data inconsistent with on-chain state");
  }

  // Verify each distribution against Merkle proof
  for (let i = 0; i < distributions.length; i++) {
    const valid = verifyMerkleProof(distributions[i], proofs[i], root);
    if (!valid) {
      throw new Error(`Invalid Merkle proof for distribution ${i}`);
    }
    await sendReward(distributions[i].staker, distributions[i].amount);
  }
}
```

---

## 0x000c — Bridge checkpoint uses single trusted relayer

```typescript
// VULNERABLE — single relayer, no SPV proof verification
async function submitCheckpoint(btcBlockHash: string, stateRoot: string) {
  // Single authorized relayer — no redundancy, single point of failure
  // No SPV proof — relayer can submit fake BTC block data
  await hostChainContract.submitCheckpoint(btcBlockHash, stateRoot, {
    from: RELAYER_ADDRESS,
  });
}
```

---

## 0x000d — BTC light client doesn't handle reorgs

```typescript
// VULNERABLE — 1 confirmation finality, no reorg detection
async function onBlockConnected(block: BitcoinBlock) {
  // BUG: accepts block at 1 confirmation as final
  if (block.confirmations >= 1) {
    await processStakingTransactions(block);
    // If this block gets reorged, staking state is now inconsistent
  }
}

async function onBlockDisconnected(block: BitcoinBlock) {
  // BUG: no handler for disconnected blocks (reorgs)
  console.log("Block disconnected:", block.hash);
  // Staking state NOT rolled back — inconsistent with Bitcoin chain
}
```

---

## 0x000e — Mass exit bypasses unbonding timelock

```typescript
// VULNERABLE — application-level timelock with overflow bypass
async function processUnbondingRequest(stakeId: string) {
  const queueLength = await db.getUnbondingQueueLength();

  // BUG: dynamic unbonding period reduction under load
  let unbondingBlocks = BASE_UNBONDING_BLOCKS;
  if (queueLength > MAX_QUEUE_SIZE) {
    unbondingBlocks = Math.max(10, unbondingBlocks - queueLength); // can drop to 10 blocks!
  }

  // BUG: application-level timelock, not Script-enforced OP_CSV
  // A colluding validator can sign an early withdrawal bypassing the app check
  await db.createUnbondingRequest(stakeId, { blocks: unbondingBlocks });
}
```

---

## 0x000f — Protocol upgrade strands existing staked UTXOs

```typescript
// VULNERABLE — v2 format change invalidates v1 pre-signed TXs
async function migrateToV2(stakeId: string) {
  const stake = await db.getStake(stakeId);

  // V2 uses different Tapscript tree structure
  // V1 pre-signed slashing TXs are now invalid (wrong witness structure)
  // If staker doesn't migrate, they're unslashable AND can't unbond
  // because v2 nodes won't process v1 transactions

  const v2StakingTx = buildV2StakingTx(stake);
  // BUG: migration window is 30 days — offline stakers lose access
  // BUG: new burn address is regular P2TR, not provably unburnable
  // BUG: no automatic migration path — requires staker to be online
}
```

---

## Quick Reference: Import Patterns to Flag

| Pattern | Risk | Checkpoint |
|---------|------|------------|
| `internalPubkey: toXOnly(validatorPubkey)` | Key-path bypass | 0x0000 |
| Incomplete `preSignedTxs` map (< 5 entries) | Missing slashing | 0x0001 |
| HD-derived staking key still accessible | Covenant bypass | 0x0002 |
| Equivocation check without `message.equals()` | False positive slash | 0x0003 |
| Slashing TX built at slash-time (not pre-signed) | Unenforceable | 0x0004 |
| `case "inactivity": executeSlashing()` | Unjust slashing | 0x0005 |
| `UNBONDING_BLOCKS = 50` (< 1008) | Insufficient window | 0x0006 |
| Missing `OP_CHECKSEQUENCEVERIFY` in unbonding leaf | Timelock bypass | 0x0007 |
| `"bc1p" + "0".repeat(58)` as burn address | Not provably unburnable | 0x0008 |
| Same `derivePath` for EOTS and spending keys | Key compromise transitive | 0x0009 |
| `updateValidator(pubkey)` without re-signing slashing TXs | Unslashable | 0x000a |
| Single `ORACLE_URL` for rewards, no Merkle proof | Selective withholding | 0x000b |
| Single `RELAYER_ADDRESS`, no SPV proof | Fake checkpoints | 0x000c |
| `block.confirmations >= 1` as finality | Reorg vulnerability | 0x000d |
| `unbondingBlocks = Math.max(10, ...)` under load | Timelock collapse | 0x000e |
| V2 migration invalidates V1 pre-signed TXs | Stranded UTXOs | 0x000f |
