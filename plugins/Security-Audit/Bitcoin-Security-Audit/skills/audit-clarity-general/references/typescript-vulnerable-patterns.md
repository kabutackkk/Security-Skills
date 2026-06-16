# TypeScript Vulnerable Patterns for Clarity Audits

Real-world vulnerable TypeScript patterns using `@stacks/transactions`, `@stacks/connect`, `@stacks/network`, and `@stacks/stacking`. Each section maps to a checkpoint in the Clarity audit skill.

---

## 0x0000 — tx-sender vs contract-caller in SDK transaction construction

### Vulnerable: Frontend assumes tx-sender safety for contract-callable functions

```typescript
// VULNERABLE — the contract uses tx-sender for auth, but this function
// is callable by other contracts. The frontend doesn't warn the user.
import {
  makeContractCall,
  broadcastTransaction,
  AnchorMode,
  PostConditionMode,
} from "@stacks/transactions";

async function withdrawFromVault(amount: number) {
  const txOptions = {
    contractAddress: "SP3FBR2AGK5H9QBDH3EEN6DF8EK8JY7RX8QJ5SVTE",
    contractName: "vault-v1",
    functionName: "withdraw", // uses tx-sender for auth — exploitable via intermediary
    functionArgs: [uintCV(amount)],
    senderKey: userPrivateKey,
    network,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Allow, // also bad — see 0x000a
  };
  const tx = await makeContractCall(txOptions);
  return broadcastTransaction(tx, network);
}
```

### Secure: Validate that the contract function uses contract-caller

```typescript
// Before building the transaction, verify the contract source uses contract-caller
import { callReadOnlyFunction, cvToJSON } from "@stacks/transactions";

// The secure contract function should use:
// (asserts! (is-eq contract-caller (var-get owner)) (err u401))
// NOT: (asserts! (is-eq tx-sender (var-get owner)) (err u401))

// If the contract uses tx-sender, warn in the UI:
// "This contract's withdraw function uses tx-sender for authorization.
//  Do not approve transactions from untrusted dApps that call this contract."
```

---

## 0x0001 — as-contract elevation via SDK error handling

### Vulnerable: Client ignores error response that triggers as-contract path

```typescript
// VULNERABLE — client doesn't check which code path the contract takes
import { makeContractCall, ClarityType } from "@stacks/transactions";

async function processAction(actionId: number) {
  const tx = await makeContractCall({
    contractAddress: VAULT_ADDRESS,
    contractName: "vault-v1",
    functionName: "process-action",
    // If action is not approved, contract hits error path with as-contract block
    // The attacker can submit unapproved action IDs to trigger the fallback
    functionArgs: [uintCV(actionId)],
    senderKey: attackerKey,
    network,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Allow,
  });
  const result = await broadcastTransaction(tx, network);
  // No check on result.ok vs result.err — doesn't verify which path executed
}
```

### Secure: Simulate first, verify execution path

```typescript
import { callReadOnlyFunction, cvToJSON } from "@stacks/transactions";

// Simulate the call first to verify it takes the intended path
async function safeProcessAction(actionId: number) {
  // Read-only check: is the action approved?
  const checkResult = await callReadOnlyFunction({
    contractAddress: VAULT_ADDRESS,
    contractName: "vault-v1",
    functionName: "get-action-status",
    functionArgs: [uintCV(actionId)],
    senderAddress: userAddress,
    network,
  });

  const status = cvToJSON(checkResult);
  if (!status.value?.["is-approved"]?.value) {
    throw new Error("Action not approved — aborting to prevent as-contract fallback");
  }

  // Only proceed if action is approved (intended code path)
  const tx = await makeContractCall({
    /* ... with PostConditionMode.Deny ... */
  });
}
```

---

## 0x0002 — Hardcoded principal in deployment scripts

### Vulnerable: Deployment uses hardcoded deployer address as owner

```typescript
// VULNERABLE — hardcoded principal prevents ownership transfer
import { makeContractDeploy, broadcastTransaction } from "@stacks/transactions";
import { readFileSync } from "fs";

async function deployVault() {
  const codeBody = readFileSync("./contracts/vault.clar", "utf-8");

  // The contract has:
  // (define-data-var contract-owner principal 'SP3FBR2AGK5H9QBDH3EEN6DF8EK8JY7RX8QJ5SVTE)
  // Instead of:
  // (define-data-var contract-owner principal tx-sender)
  //
  // This means the deployer's address is baked into the contract.
  // If deploying from a different key, the owner is wrong.
  // Ownership can never change because it's a literal, not a variable lookup.

  const tx = await makeContractDeploy({
    codeBody,
    contractName: "vault-v1",
    senderKey: deployerPrivateKey, // might be a different key than the hardcoded principal!
    network,
    anchorMode: AnchorMode.Any,
  });
  return broadcastTransaction(tx, network);
}
```

### Secure: Verify contract uses tx-sender for initial owner

```typescript
// Pre-deployment check: scan contract source for hardcoded principals
function validateContractSource(source: string): string[] {
  const issues: string[] = [];
  const principalRegex = /(?:define-data-var|define-constant)\s+\S+\s+principal\s+'S[PM][A-Z0-9]+/g;
  const matches = source.match(principalRegex);
  if (matches) {
    issues.push(
      `Hardcoded principal(s) found: ${matches.join(", ")}. ` +
        `Use tx-sender for deployer-relative initialization.`
    );
  }
  return issues;
}
```

---

## 0x0003 — ft-transfer? without sender authorization

### Vulnerable: SDK wrapper doesn't enforce sender === signer

```typescript
// VULNERABLE — builds transfer TX without checking sender matches signer
import { makeContractCall, standardPrincipalCV, uintCV } from "@stacks/transactions";

async function transferTokens(
  tokenContract: string,
  amount: number,
  sender: string, // user-supplied — could be anyone's address!
  recipient: string
) {
  const [contractAddr, contractName] = tokenContract.split(".");
  const tx = await makeContractCall({
    contractAddress: contractAddr,
    contractName,
    functionName: "transfer",
    functionArgs: [
      uintCV(amount),
      standardPrincipalCV(sender), // NOT validated against senderKey!
      standardPrincipalCV(recipient),
      noneCV(), // memo
    ],
    senderKey: userPrivateKey, // this is the TX signer, but sender param is arbitrary
    network,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Allow,
  });
  return broadcastTransaction(tx, network);
}

// If the contract's transfer function is missing:
// (asserts! (is-eq tx-sender sender) (err u401))
// Then the attacker's TX succeeds, draining the victim's tokens.
```

### Secure: Client-side + contract-side validation

```typescript
import { getAddressFromPrivateKey, TransactionVersion } from "@stacks/transactions";

async function safeTransferTokens(
  tokenContract: string,
  amount: number,
  sender: string,
  recipient: string,
  senderKey: string
) {
  // Client-side: verify sender matches the signing key
  const signerAddress = getAddressFromPrivateKey(
    senderKey,
    TransactionVersion.Mainnet
  );
  if (signerAddress !== sender) {
    throw new Error(
      `Sender ${sender} does not match signer ${signerAddress}. ` +
        `This would fail at the contract level (SIP-010 requires tx-sender == sender).`
    );
  }

  // Also use Deny mode + FT post-condition
  const postConditions = [
    makeStandardFungiblePostCondition(
      sender,
      FungibleConditionCode.Equal,
      amount,
      createAssetInfo(contractAddr, contractName, tokenName)
    ),
  ];

  const tx = await makeContractCall({
    /* ... postConditionMode: PostConditionMode.Deny, postConditions ... */
  });
}
```

---

## 0x0004 — SIP-010/009 non-compliance in SDK integration

### Vulnerable: Frontend trusts get-balance without verifying SIP compliance

```typescript
// VULNERABLE — trusts token contract's get-balance without verifying compliance
import { callReadOnlyFunction, cvToJSON, uintCV } from "@stacks/transactions";

async function getPortfolioValue(tokens: TokenInfo[], userAddress: string) {
  let totalValue = 0;

  for (const token of tokens) {
    // No verification that this contract actually implements SIP-010 correctly
    // A malicious token could return inflated balances
    const result = await callReadOnlyFunction({
      contractAddress: token.address,
      contractName: token.name,
      functionName: "get-balance",
      functionArgs: [standardPrincipalCV(userAddress)],
      senderAddress: userAddress,
      network,
    });

    const balance = cvToJSON(result).value;
    // Trusting this value for collateral/lending decisions is dangerous
    totalValue += balance * token.price;
  }

  return totalValue;
}
```

### Secure: Verify SIP-010 compliance before trusting

```typescript
// Check that the contract implements the full SIP-010 interface
async function verifySIP010Compliance(contractId: string): Promise<boolean> {
  const [addr, name] = contractId.split(".");
  const requiredFunctions = [
    "transfer",
    "get-name",
    "get-symbol",
    "get-decimals",
    "get-balance",
    "get-total-supply",
    "get-token-uri",
  ];

  try {
    const source = await fetchContractSource(addr, name, network);
    // Verify all required functions exist
    for (const fn of requiredFunctions) {
      if (!source.includes(`(define-public (${fn}`) && !source.includes(`(define-read-only (${fn}`)) {
        return false;
      }
    }
    // Verify transfer checks tx-sender == sender
    if (!source.includes("(is-eq tx-sender sender)")) {
      console.warn(`${contractId}: transfer may not enforce sender authorization`);
      return false;
    }
    return true;
  } catch {
    return false;
  }
}
```

---

## 0x0005 — Unrestricted mint callable from SDK

### Vulnerable: Admin dashboard calls mint without verifying access control

```typescript
// VULNERABLE — the contract's mint function has NO access control
// Anyone who discovers this endpoint can mint unlimited tokens
async function mintRewardTokens(recipient: string, amount: number) {
  const tx = await makeContractCall({
    contractAddress: REWARD_TOKEN_ADDRESS,
    contractName: "reward-token",
    functionName: "mint-tokens", // (define-public (mint-tokens ...) (ft-mint? ...))
    // Contract is missing: (asserts! (is-eq contract-caller (var-get minter)) (err u401))
    functionArgs: [uintCV(amount), standardPrincipalCV(recipient)],
    senderKey: anyonePrivateKey, // literally anyone can call this
    network,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Allow,
  });
  return broadcastTransaction(tx, network);
}
```

### Detection: Static analysis of mint functions

```typescript
function auditMintAccess(contractSource: string): string[] {
  const issues: string[] = [];
  const mintRegex = /\(define-public\s+\((\S+)[^)]*\)[\s\S]*?\(ft-mint\?/g;
  let match;
  while ((match = mintRegex.exec(contractSource)) !== null) {
    const fnName = match[1];
    // Extract function body up to matching closing paren
    const fnBody = extractFunctionBody(contractSource, match.index);
    if (!fnBody.includes("asserts!") && !fnBody.includes("contract-caller")) {
      issues.push(`Mint function '${fnName}' has no access control — anyone can mint`);
    }
    if (!fnBody.includes("max-supply") && !fnBody.includes("supply-cap")) {
      issues.push(`Mint function '${fnName}' has no supply cap check`);
    }
  }
  return issues;
}
```

---

## 0x0006 — List duplication in SDK call construction

### Vulnerable: Frontend sends duplicate asset IDs in list parameter

```typescript
// VULNERABLE — no deduplication before sending list to contract
import { listCV, uintCV } from "@stacks/transactions";

async function calculateCollateral(assetIds: number[]) {
  // User/attacker controls assetIds — could be [1, 1, 1, 1, 1]
  // Contract's fold accumulates value per element without uniqueness check
  const tx = await makeContractCall({
    contractAddress: LENDING_ADDRESS,
    contractName: "lending-pool",
    functionName: "calculate-collateral",
    functionArgs: [
      listCV(assetIds.map((id) => uintCV(id))), // no dedup!
    ],
    senderKey: userPrivateKey,
    network,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Allow,
  });
  return broadcastTransaction(tx, network);
}
```

### Secure: Deduplicate + warn on client side

```typescript
async function safeCalculateCollateral(assetIds: number[]) {
  const unique = [...new Set(assetIds)];
  if (unique.length !== assetIds.length) {
    console.warn(
      `Duplicate asset IDs removed: ${assetIds.length} -> ${unique.length}. ` +
        `Contract should also enforce uniqueness (Zest Protocol vulnerability).`
    );
  }

  const tx = await makeContractCall({
    contractAddress: LENDING_ADDRESS,
    contractName: "lending-pool",
    functionName: "calculate-collateral",
    functionArgs: [listCV(unique.map((id) => uintCV(id)))],
    senderKey: userPrivateKey,
    network,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Deny,
  });
  return broadcastTransaction(tx, network);
}
```

---

## 0x0007 — Unvalidated trait reference passed from frontend

### Vulnerable: User-supplied contract address used as trait parameter

```typescript
// VULNERABLE — user can specify ANY contract as the token to deposit
async function depositCollateral(
  tokenContractId: string, // user input from dropdown or URL param
  amount: number
) {
  const [tokenAddr, tokenName] = tokenContractId.split(".");

  const tx = await makeContractCall({
    contractAddress: DEFI_PROTOCOL_ADDRESS,
    contractName: "lending-v2",
    functionName: "deposit-collateral",
    functionArgs: [
      contractPrincipalCV(tokenAddr, tokenName), // attacker's malicious contract
      uintCV(amount),
    ],
    senderKey: userPrivateKey,
    network,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Allow,
  });
  return broadcastTransaction(tx, network);
}
// If the contract doesn't validate the trait reference against a whitelist,
// the attacker's contract can return fake balances or no-op on transfers
```

### Secure: Validate token against on-chain whitelist

```typescript
async function safeDeposit(tokenContractId: string, amount: number) {
  const [tokenAddr, tokenName] = tokenContractId.split(".");

  // Check on-chain whitelist before submitting
  const isApproved = await callReadOnlyFunction({
    contractAddress: DEFI_PROTOCOL_ADDRESS,
    contractName: "lending-v2",
    functionName: "is-approved-token",
    functionArgs: [contractPrincipalCV(tokenAddr, tokenName)],
    senderAddress: userAddress,
    network,
  });

  if (cvToJSON(isApproved).value !== true) {
    throw new Error(`Token ${tokenContractId} is not in the approved whitelist`);
  }

  // Proceed with Deny mode post-conditions
}
```

---

## 0x0008 — unwrap-panic triggered from SDK

### Vulnerable: Frontend sends request that triggers unwrap-panic in batch processor

```typescript
// VULNERABLE — if any map-get? returns none, the contract panics
// and reverts the entire batch transaction
async function claimAllRewards(epochIds: number[]) {
  for (const epochId of epochIds) {
    const tx = await makeContractCall({
      contractAddress: STAKING_ADDRESS,
      contractName: "staking-v1",
      functionName: "claim-epoch-reward",
      // Contract does: (unwrap-panic (map-get? epoch-rewards { epoch: epoch-id }))
      // If epoch doesn't exist, entire TX reverts — DoS for legitimate claims
      functionArgs: [uintCV(epochId)],
      senderKey: userPrivateKey,
      network,
      anchorMode: AnchorMode.Any,
      postConditionMode: PostConditionMode.Deny,
    });
    const result = await broadcastTransaction(tx, network);
    // Attacker deletes an epoch entry or claims a nonexistent epoch to DoS others
  }
}
```

### Secure: Pre-check existence before calling

```typescript
async function safeClaimRewards(epochIds: number[]) {
  for (const epochId of epochIds) {
    // Check if the epoch reward exists before claiming
    const exists = await callReadOnlyFunction({
      contractAddress: STAKING_ADDRESS,
      contractName: "staking-v1",
      functionName: "get-epoch-reward",
      functionArgs: [uintCV(epochId)],
      senderAddress: userAddress,
      network,
    });

    if (cvToJSON(exists).value === null) {
      console.warn(`Epoch ${epochId} has no reward entry — skipping to avoid panic`);
      continue;
    }

    // Safe to call — entry exists
    const tx = await makeContractCall({ /* ... */ });
  }
}
```

---

## 0x0009 — default-to zero bypass in SDK value checks

### Vulnerable: Frontend trusts contract return value that uses default-to u0

```typescript
// VULNERABLE — contract returns 0 for non-existent entries via default-to
// Frontend uses this to determine "no debt" — but it could mean "entry missing"
async function checkCanWithdraw(user: string): Promise<boolean> {
  const debtResult = await callReadOnlyFunction({
    contractAddress: LENDING_ADDRESS,
    contractName: "lending-v1",
    functionName: "get-user-debt",
    // Contract: (default-to u0 (get amount (map-get? debts { user: user })))
    // Returns 0 for both "debt is zero" AND "user has no entry"
    functionArgs: [standardPrincipalCV(user)],
    senderAddress: user,
    network,
  });

  const debt = Number(cvToJSON(debtResult).value);
  // Attacker with no debt entry can withdraw all collateral
  // because "no entry" looks the same as "zero debt"
  return debt === 0;
}
```

### Secure: Distinguish between "zero" and "none"

```typescript
// Use a read-only function that returns (optional ...) to distinguish
async function safeCheckCanWithdraw(user: string): Promise<boolean> {
  const debtResult = await callReadOnlyFunction({
    contractAddress: LENDING_ADDRESS,
    contractName: "lending-v1",
    functionName: "get-user-debt-optional", // returns (optional { amount: uint })
    functionArgs: [standardPrincipalCV(user)],
    senderAddress: user,
    network,
  });

  const parsed = cvToJSON(debtResult);
  if (parsed.value === null) {
    // No entry — user never deposited. Cannot withdraw.
    return false;
  }
  return parsed.value.amount.value === 0;
}
```

---

## 0x000a — PostConditionMode.Allow in SDK usage

### Vulnerable: dApp uses Allow mode for all transactions

```typescript
// VULNERABLE — PostConditionMode.Allow lets contract make hidden transfers
import {
  makeContractCall,
  PostConditionMode,
  AnchorMode,
} from "@stacks/transactions";

async function buyNFT(nftId: number, price: number) {
  const tx = await makeContractCall({
    contractAddress: MARKETPLACE_ADDRESS,
    contractName: "marketplace-v1",
    functionName: "buy-nft",
    functionArgs: [uintCV(nftId)],
    senderKey: buyerPrivateKey,
    network,
    anchorMode: AnchorMode.Any,
    // DANGEROUS: any transfer the contract makes will succeed silently
    // A malicious marketplace could transfer extra tokens from the buyer
    postConditionMode: PostConditionMode.Allow,
  });
  return broadcastTransaction(tx, network);
}
```

### Secure: Always use Deny mode with explicit post-conditions

```typescript
import {
  makeContractCall,
  PostConditionMode,
  makeStandardSTXPostCondition,
  makeContractNonFungiblePostCondition,
  FungibleConditionCode,
  NonFungibleConditionCode,
  createAssetInfo,
  bufferCVFromString,
} from "@stacks/transactions";

async function safeBuyNFT(nftId: number, price: number) {
  const postConditions = [
    // Buyer sends exactly the listing price in STX
    makeStandardSTXPostCondition(
      buyerAddress,
      FungibleConditionCode.Equal,
      price
    ),
    // Seller sends exactly this NFT to buyer
    makeContractNonFungiblePostCondition(
      MARKETPLACE_ADDRESS,
      "marketplace-v1",
      NonFungibleConditionCode.Sends,
      createAssetInfo(NFT_ADDRESS, "my-nft", "my-nft"),
      uintCV(nftId)
    ),
  ];

  const tx = await makeContractCall({
    contractAddress: MARKETPLACE_ADDRESS,
    contractName: "marketplace-v1",
    functionName: "buy-nft",
    functionArgs: [uintCV(nftId)],
    senderKey: buyerPrivateKey,
    network,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Deny, // REQUIRED
    postConditions,
  });
  return broadcastTransaction(tx, network);
}
```

---

## 0x000b — State changes invisible to post-conditions

### Vulnerable: Commission callback modifies price state undetected

```typescript
// VULNERABLE — post-conditions cover the NFT and STX transfers,
// but the commission contract modifies map state invisibly
async function buyWithCommission(nftId: number, price: number) {
  const postConditions = [
    makeStandardSTXPostCondition(buyerAddress, FungibleConditionCode.Equal, price),
    // This covers the asset transfers — looks safe!
  ];

  const tx = await makeContractCall({
    contractAddress: MARKETPLACE_ADDRESS,
    contractName: "marketplace-v1",
    functionName: "buy-nft",
    // The commission contract called during this TX can do:
    // (map-set listings { id: u42 } { price: u0, seller: attacker })
    // Post-conditions cannot detect this map modification
    functionArgs: [
      uintCV(nftId),
      contractPrincipalCV(COMMISSION_ADDR, "commission-v1"),
    ],
    senderKey: buyerPrivateKey,
    network,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Deny,
    postConditions,
  });
  return broadcastTransaction(tx, network);
}
```

### Detection: Verify commission contract is whitelisted

```typescript
// Before submitting, verify the commission contract against on-chain whitelist
async function verifyCommissionContract(commissionAddr: string, commissionName: string) {
  const isApproved = await callReadOnlyFunction({
    contractAddress: MARKETPLACE_ADDRESS,
    contractName: "marketplace-v1",
    functionName: "is-approved-commission",
    functionArgs: [contractPrincipalCV(commissionAddr, commissionName)],
    senderAddress: userAddress,
    network,
  });

  if (cvToJSON(isApproved).value !== true) {
    throw new Error(
      `Commission contract ${commissionAddr}.${commissionName} is not approved. ` +
        `Untrusted commission contracts can modify state invisibly.`
    );
  }
}
```

---

## 0x000c — map-set vs map-insert in transaction construction

### Vulnerable: Frontend allows re-registration that overwrites existing data

```typescript
// VULNERABLE — calls a function that uses map-set for registration
// An attacker can overwrite another user's listing/registration
async function registerName(name: string) {
  const tx = await makeContractCall({
    contractAddress: BNS_CLONE_ADDRESS,
    contractName: "name-registry",
    functionName: "register-name",
    // Contract uses: (map-set names { name: name } { owner: tx-sender })
    // Should use: (asserts! (map-insert names ...) (err u409))
    // Attacker can overwrite existing registrations
    functionArgs: [bufferCVFromString(name)],
    senderKey: attackerPrivateKey,
    network,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Deny,
  });
  return broadcastTransaction(tx, network);
}
```

### Detection: Static analysis for map-set in create operations

```typescript
function auditMapOperations(source: string): string[] {
  const issues: string[] = [];

  // Find functions that look like create/register operations but use map-set
  const createFnRegex = /\(define-public\s+\((register|create|claim|init)[^)]*\)[\s\S]*?\)/g;
  let match;
  while ((match = createFnRegex.exec(source)) !== null) {
    const fnBody = extractFunctionBody(source, match.index);
    if (fnBody.includes("map-set") && !fnBody.includes("map-get?")) {
      issues.push(
        `Function '${match[1]}...' uses map-set without existence check. ` +
          `Create/register operations should use map-insert to prevent overwrites.`
      );
    }
  }
  return issues;
}
```

---

## 0x000d — Unhandled contract-call? errors in multi-call transactions

### Vulnerable: Multi-step TX doesn't handle intermediate call failures

```typescript
// VULNERABLE — builds a multi-step transaction without simulating each step
async function liquidateAndRedistribute(positionId: number) {
  const tx = await makeContractCall({
    contractAddress: LENDING_ADDRESS,
    contractName: "lending-v1",
    functionName: "liquidate-position",
    // Contract does:
    // (let ((price (unwrap-panic (contract-call? .oracle get-price "BTC"))))
    //   ...)
    // If oracle returns (err ...), unwrap-panic aborts the entire TX
    // Attacker can manipulate oracle to return err, blocking all liquidations
    functionArgs: [uintCV(positionId)],
    senderKey: liquidatorPrivateKey,
    network,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Deny,
  });
  return broadcastTransaction(tx, network);
}
```

### Secure: Simulate first, check oracle health

```typescript
async function safeLiquidate(positionId: number) {
  // 1. Check oracle is responding correctly
  const oracleResult = await callReadOnlyFunction({
    contractAddress: ORACLE_ADDRESS,
    contractName: "oracle-v1",
    functionName: "get-price",
    functionArgs: [stringAsciiCV("BTC")],
    senderAddress: liquidatorAddress,
    network,
  });

  const oracleResponse = cvToJSON(oracleResult);
  if (oracleResponse.type === "err") {
    throw new Error("Oracle returning errors — liquidation would panic. Wait for oracle recovery.");
  }

  // 2. Simulate the full liquidation
  const simResult = await callReadOnlyFunction({
    contractAddress: LENDING_ADDRESS,
    contractName: "lending-v1",
    functionName: "simulate-liquidation",
    functionArgs: [uintCV(positionId)],
    senderAddress: liquidatorAddress,
    network,
  });

  if (cvToJSON(simResult).type === "err") {
    throw new Error("Liquidation simulation failed — do not submit");
  }

  // 3. Submit with proper post-conditions
  const tx = await makeContractCall({ /* ... */ });
}
```

---

## 0x000e — Missing admin access control in parameter update calls

### Vulnerable: Admin UI doesn't verify on-chain access control exists

```typescript
// VULNERABLE — admin dashboard sends parameter updates
// but the contract function has NO access control
async function updateRewardRate(newRate: number) {
  // Admin UI assumes only admins have this page
  // But the contract's set-reward-rate has no asserts! guard
  // Anyone who knows the function name can call it
  const tx = await makeContractCall({
    contractAddress: STAKING_ADDRESS,
    contractName: "staking-v1",
    functionName: "set-reward-rate",
    // Contract: (define-public (set-reward-rate (rate uint)) (begin (var-set reward-rate rate) (ok true)))
    // NO access control — anyone can set the reward rate!
    functionArgs: [uintCV(newRate)],
    senderKey: adminPrivateKey,
    network,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Deny,
  });
  return broadcastTransaction(tx, network);
}
```

### Detection: Audit all state-modifying functions for access control

```typescript
function auditAdminFunctions(source: string): string[] {
  const issues: string[] = [];
  const stateModifyingRegex = /\(define-public\s+\((\S+)[^)]*\)[\s\S]*?\(var-set\s/g;
  let match;
  while ((match = stateModifyingRegex.exec(source)) !== null) {
    const fnName = match[1];
    const fnBody = extractFunctionBody(source, match.index);
    if (!fnBody.includes("asserts!") && !fnBody.includes("contract-caller")) {
      issues.push(
        `State-modifying function '${fnName}' has no access control. ` +
          `Any user can change protocol parameters.`
      );
    }
  }
  return issues;
}
```

---

## 0x000f — Hardcoded block-time assumptions in SDK calculations

### Vulnerable: Frontend calculates deadlines using 144 blocks = 1 day

```typescript
// VULNERABLE — assumes 144 Stacks blocks per day (pre-Nakamoto)
// Post-Nakamoto: Stacks blocks are ~5 seconds, so 144 blocks ≈ 12 minutes
const BLOCKS_PER_DAY = 144; // WRONG post-Nakamoto upgrade

async function createTimedListing(nftId: number, durationDays: number) {
  const currentBlockHeight = await getStacksBlockHeight(network);
  const expiryBlock = currentBlockHeight + durationDays * BLOCKS_PER_DAY;

  const tx = await makeContractCall({
    contractAddress: MARKETPLACE_ADDRESS,
    contractName: "marketplace-v1",
    functionName: "create-listing",
    functionArgs: [
      uintCV(nftId),
      uintCV(expiryBlock), // listing "expires in 7 days" actually expires in ~84 minutes
    ],
    senderKey: sellerPrivateKey,
    network,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Deny,
  });
  return broadcastTransaction(tx, network);
}
```

### Secure: Use burn-block-height for time-sensitive operations

```typescript
// Post-Nakamoto: use burn-block-height (Bitcoin blocks, ~10 min each)
const BTC_BLOCKS_PER_DAY = 144; // Bitcoin blocks are still ~10 minutes

async function safeCreateTimedListing(nftId: number, durationDays: number) {
  // Use burn-block-height for reliable timing
  const currentBurnHeight = await getBurnBlockHeight(network);
  const expiryBurnBlock = currentBurnHeight + durationDays * BTC_BLOCKS_PER_DAY;

  const tx = await makeContractCall({
    contractAddress: MARKETPLACE_ADDRESS,
    contractName: "marketplace-v2",
    functionName: "create-listing",
    // Contract should use burn-block-height for deadline comparison:
    // (asserts! (< burn-block-height (get expiry listing)) (err u410))
    functionArgs: [
      uintCV(nftId),
      uintCV(expiryBurnBlock),
    ],
    senderKey: sellerPrivateKey,
    network,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Deny,
  });
  return broadcastTransaction(tx, network);
}
```

---

## 0x0010 — Bridge integration with unvalidated cross-chain messages

### Vulnerable: Bridge relayer accepts unverified cross-chain mint requests

```typescript
// VULNERABLE — bridge relayer service trusts incoming messages without proof
import express from "express";
import { makeContractCall, bufferCV, uintCV, standardPrincipalCV } from "@stacks/transactions";

const app = express();
app.use(express.json());

app.post("/api/bridge/mint", async (req, res) => {
  const { sourceChain, sourceTxHash, recipient, amount, sourceAddress } = req.body;

  // NO VERIFICATION:
  // - No SPV proof of the source transaction
  // - No multi-sig attestation
  // - No sourceAddress format validation
  // - No replay protection (same sourceTxHash can be submitted multiple times)
  // - No rate limiting or amount caps

  const tx = await makeContractCall({
    contractAddress: BRIDGE_ADDRESS,
    contractName: "bridge-v1",
    functionName: "bridge-mint",
    functionArgs: [
      standardPrincipalCV(recipient),
      uintCV(amount),
      bufferCV(Buffer.from(sourceTxHash, "hex")),
      bufferCV(Buffer.from(sourceAddress)), // no format validation!
    ],
    senderKey: relayerPrivateKey, // single relayer key — no multi-sig
    network,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Allow,
  });

  const result = await broadcastTransaction(tx, network);
  res.json({ txId: result.txid });
});
```

### Secure: Verify proofs + multi-sig + rate limits

```typescript
import { verifyMerkleProof } from "./bitcoin-spv";
import { verifyMultiSig } from "./multisig";

app.post("/api/bridge/mint", async (req, res) => {
  const { sourceChain, sourceTxHash, recipient, amount, sourceAddress, proof, signatures } = req.body;

  // 1. Validate source address format
  if (sourceChain === "bitcoin" && !isValidBitcoinAddress(sourceAddress)) {
    return res.status(400).json({ error: "Invalid Bitcoin address format" });
  }
  if (!isValidStacksAddress(recipient)) {
    return res.status(400).json({ error: "Invalid Stacks address format" });
  }

  // 2. Verify SPV proof against Bitcoin block headers
  const proofValid = await verifyMerkleProof(sourceTxHash, proof, sourceChain);
  if (!proofValid) {
    return res.status(400).json({ error: "Invalid SPV proof" });
  }

  // 3. Verify multi-sig attestation (3-of-5 relayers)
  const sigValid = verifyMultiSig(signatures, { sourceTxHash, recipient, amount }, 3);
  if (!sigValid) {
    return res.status(400).json({ error: "Insufficient relayer signatures" });
  }

  // 4. Check replay protection
  if (await isAlreadyProcessed(sourceTxHash)) {
    return res.status(409).json({ error: "Transaction already processed" });
  }

  // 5. Check rate limits
  if (amount > DAILY_MINT_CAP || (await getDailyMintTotal()) + amount > DAILY_MINT_CAP) {
    return res.status(429).json({ error: "Daily mint cap exceeded" });
  }

  // 6. Submit with proper post-conditions
  const tx = await makeContractCall({
    /* ... PostConditionMode.Deny ... */
  });
});
```

---

## Quick Reference: Import Patterns to Flag

When auditing TypeScript code interacting with Clarity contracts, flag these patterns:

| Pattern | Risk | Checkpoint |
|---------|------|------------|
| `PostConditionMode.Allow` | Hidden transfers possible | 0x000a |
| `unwrap-panic` in contract source called from TS | DoS vector | 0x0008 |
| `makeContractCall` without `postConditions` array | No transfer protection | 0x000a |
| `contractPrincipalCV(userInput, ...)` as trait param | Trait redirection | 0x0007 |
| `listCV(...)` without deduplication | Duplication attack | 0x0006 |
| Hardcoded `'SP...` in contract source | Frozen ownership | 0x0002 |
| `*  144` or `BLOCKS_PER_DAY = 144` with `block-height` | Post-Nakamoto timing bug | 0x000f |
| No `(is-eq tx-sender sender)` before `ft-transfer?` | Token theft | 0x0003 |
| Single `senderKey` for bridge relayer | No multi-sig | 0x0010 |
| `callReadOnlyFunction` result used for pricing without verification | Oracle manipulation | 0x000d |
