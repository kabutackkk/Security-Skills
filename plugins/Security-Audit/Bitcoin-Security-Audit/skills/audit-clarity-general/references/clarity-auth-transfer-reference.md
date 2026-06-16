# Clarity Authentication Model & Transfer Safety Reference

This document provides reference tables, decision flowcharts, and secure pattern templates for Clarity smart contract authentication, token transfer authorization, and post-condition mechanics.

---

## 1. Principal Identity Model

### tx-sender vs contract-caller vs as-contract

| Property | `tx-sender` | `contract-caller` | `as-contract` |
|---|---|---|---|
| **Represents** | Original transaction signer | Immediate calling principal | The contract's own principal |
| **Persists across contract-call?** | Yes — always the original signer | No — changes to the calling contract at each hop | Temporary — only within the `as-contract` block |
| **Solidity Analog** | `tx.origin` | `msg.sender` | Contract executing as itself (self-call) |
| **Safe for authorization?** | Only for direct entry points | Yes — recommended for most authorization | Not for authorization — for contract self-actions |
| **Risk** | Intermediary inherits user identity | None if used correctly | Unintended code paths grant elevated identity |

### Identity Resolution Example

```
User (wallet) → Contract A → Contract B → Contract C

Inside Contract C:
  tx-sender       = User (wallet)     ← SAME as original signer
  contract-caller = Contract B        ← IMMEDIATE caller
```

### Solidity Developer Translation Guide

| Solidity Pattern | Clarity Equivalent | Notes |
|---|---|---|
| `require(msg.sender == owner)` | `(asserts! (is-eq contract-caller (var-get owner)) (err u401))` | Use `contract-caller` not `tx-sender` |
| `require(tx.origin == msg.sender)` | `(asserts! (is-eq tx-sender contract-caller) ...)` | Anti-contract check (same as Solidity) |
| `address(this)` | `(as-contract tx-sender)` inside `as-contract` block | Contract's own principal |
| `onlyOwner modifier` | `(asserts! (is-eq contract-caller (var-get owner)) (err u401))` at function start | No modifier syntax — inline assert |

---

## 2. Principal Identity Decision Flowchart

```
Who should the contract check for authorization?

Is this function ONLY called by end users (never by other contracts)?
│
├── yes ──> tx-sender is acceptable (but contract-caller also works)
│
└── no ──> Is this function callable by other contracts via contract-call?
    │
    ├── yes ──> MUST use contract-caller
    │           (tx-sender would let intermediary inherit user identity)
    │
    └── Should the contract act on its own behalf (transfer its own assets)?
        │
        ├── yes ──> Use (as-contract ...) with STRICT pre-validation
        │           - All auth checks BEFORE as-contract block
        │           - Minimal scope inside as-contract
        │           - No user-controlled paths into as-contract
        │
        └── no ──> Use contract-caller for standard authorization
```

---

## 3. Token Transfer Authorization Differences

### stx-transfer? vs ft-transfer? vs nft-transfer?

| Function | Built-in Sender Check | Explicit Authorization Required | Risk Level |
|---|---|---|---|
| `(stx-transfer? amount sender recipient)` | Yes — requires `tx-sender == sender` | No (built-in) | Low |
| `(ft-transfer? token amount sender recipient)` | **No** — any caller can specify any sender | **Yes — MUST add explicit check** | **Critical** |
| `(nft-transfer? token id sender recipient)` | **No** — any caller can specify any sender | **Yes — MUST add explicit check** | **Critical** |

### Why This Matters

`stx-transfer?` has a built-in safety check: it verifies `tx-sender` equals the `sender` parameter. This is **not** the case for `ft-transfer?` and `nft-transfer?` — they transfer from any specified sender without verification. This is the single most common Clarity vulnerability.

### Authorization Check Matrix

| Operation | Required Check | Pattern |
|---|---|---|
| Direct user transfer (SIP-010) | Sender is tx-sender | `(asserts! (is-eq tx-sender sender) (err u401))` |
| Approved operator transfer | Operator is authorized | `(asserts! (is-approved-operator contract-caller sender) (err u403))` |
| Contract self-transfer | Preceded by business logic auth | `(as-contract (ft-transfer? ...))` with prior validation |
| Admin transfer | Admin is stored principal | `(asserts! (is-eq contract-caller (var-get admin)) (err u401))` |

---

## 4. Secure Authorization Pattern Templates

### SIP-010 Compliant Transfer

```clarity
(define-public (transfer (amount uint) (sender principal) (recipient principal) (memo (optional (buff 34))))
  (begin
    ;; REQUIRED by SIP-010: verify caller is the sender
    (asserts! (is-eq tx-sender sender) (err u401))
    ;; Execute transfer
    (try! (ft-transfer? my-token amount sender recipient))
    ;; Emit memo event (required by SIP-010 for wallet indexing)
    (match memo to-print (print to-print) 0x)
    (ok true)
  )
)
```

### Admin-Only Function

```clarity
(define-data-var contract-owner principal tx-sender)

(define-public (set-parameter (new-value uint))
  (begin
    ;; Compare against STORED principal — not hardcoded, not parameter
    (asserts! (is-eq contract-caller (var-get contract-owner)) (err u401))
    (var-set some-parameter new-value)
    ;; Emit event for transparency
    (print { event: "parameter-updated", value: new-value, caller: contract-caller })
    (ok true)
  )
)
```

### Two-Step Ownership Transfer

```clarity
(define-data-var contract-owner principal tx-sender)
(define-data-var pending-owner (optional principal) none)

(define-public (set-pending-owner (new-owner principal))
  (begin
    (asserts! (is-eq contract-caller (var-get contract-owner)) (err u401))
    (var-set pending-owner (some new-owner))
    (print { event: "pending-owner-set", new-owner: new-owner })
    (ok true)
  )
)

(define-public (accept-ownership)
  (begin
    (asserts! (is-eq contract-caller (unwrap! (var-get pending-owner) (err u403))) (err u401))
    (var-set contract-owner contract-caller)
    (var-set pending-owner none)
    (print { event: "ownership-transferred", new-owner: contract-caller })
    (ok true)
  )
)
```

### Trait Reference Whitelist

```clarity
(define-map approved-tokens principal bool)

(define-public (add-approved-token (token principal))
  (begin
    (asserts! (is-eq contract-caller (var-get contract-owner)) (err u401))
    (ok (map-set approved-tokens token true))
  )
)

(define-private (is-approved-token (token <ft-trait>))
  (default-to false (map-get? approved-tokens (contract-of token)))
)

(define-public (deposit (token <ft-trait>) (amount uint))
  (begin
    ;; Validate trait reference against whitelist BEFORE use
    (asserts! (is-approved-token token) (err u403))
    ;; Now safe to call trait functions
    (try! (contract-call? token transfer amount tx-sender (as-contract tx-sender) none))
    (ok true)
  )
)
```

---

## 5. SIP Trait Definitions

### SIP-010: Fungible Token Standard

Required functions:
```clarity
(define-trait ft-trait
  (
    (transfer (uint principal principal (optional (buff 34))) (response bool uint))
    (get-name () (response (string-ascii 32) uint))
    (get-symbol () (response (string-ascii 32) uint))
    (get-decimals () (response uint uint))
    (get-balance (principal) (response uint uint))
    (get-total-supply () (response uint uint))
    (get-token-uri () (response (optional (string-utf8 256)) uint))
  )
)
```

Security requirements:
- `transfer` MUST verify `(is-eq tx-sender sender)`
- `transfer` MUST emit a `(print ...)` event for post-condition detection
- `get-balance` and `get-total-supply` MUST return accurate values
- `get-decimals` MUST return consistent value

### SIP-009: Non-Fungible Token Standard

Required functions:
```clarity
(define-trait nft-trait
  (
    (get-last-token-id () (response uint uint))
    (get-token-uri (uint) (response (optional (string-utf8 256)) uint))
    (get-owner (uint) (response (optional principal) uint))
    (transfer (uint principal principal) (response bool uint))
  )
)
```

Security requirements:
- `transfer` MUST verify sender is the current owner
- `transfer` MUST verify `(is-eq tx-sender sender)`
- `get-owner` MUST return accurate ownership state

### SIP-013: Semi-Fungible Token Standard

Required functions:
```clarity
(define-trait semi-fungible-token-trait
  (
    (transfer (uint uint principal principal) (response bool uint))
    (transfer-many ((list 200 { token-id: uint, amount: uint, sender: principal, recipient: principal })) (response bool uint))
    (get-balance (uint principal) (response uint uint))
    (get-overall-balance (principal) (response uint uint))
    (get-total-supply (uint) (response uint uint))
    (get-overall-supply () (response uint uint))
    (get-decimals (uint) (response uint uint))
    (get-token-uri (uint) (response (optional (string-utf8 256)) uint))
  )
)
```

Security requirements:
- `transfer` MUST verify `(is-eq tx-sender sender)` for each transfer
- `transfer-many` MUST verify sender authorization for each entry in the list
- `transfer-many` MUST validate element uniqueness if cumulative effects apply

---

## 6. Post-Condition Mechanics

### What Post-Conditions Can Protect

| Asset Type | Post-Condition Support | Coverage |
|---|---|---|
| STX transfers | Yes | Amount and sender/recipient constraints |
| Fungible token transfers | Yes | Amount and sender/recipient constraints |
| NFT transfers | Yes | Token ID and sender/recipient constraints |

### What Post-Conditions Cannot Protect

| State Change Type | Post-Condition Support | Risk |
|---|---|---|
| `(map-set ...)` / `(map-insert ...)` | **No** | State can be modified invisibly |
| `(var-set ...)` | **No** | Configuration can be changed invisibly |
| `(map-delete ...)` | **No** | Data can be erased invisibly |
| NFT metadata changes | **No** | Properties can be altered after purchase |
| Permission/role changes | **No** | Access control can be modified invisibly |

### Allow vs Deny Mode

| Mode | Behavior | Security |
|---|---|---|
| `allow` | Listed transfers are checked; unlisted transfers proceed silently | **Unsafe** — hidden transfers possible |
| `deny` | All transfers must match a post-condition; unlisted transfers abort the transaction | **Recommended** — no hidden transfers |

### Post-Condition Decision Flowchart for Auditors

```
Auditing a user-facing transaction:

Does the transaction involve asset transfers?
│
├── yes ──> Are post-conditions set to DENY mode?
│           │
│           ├── yes ──> Do post-conditions cover ALL transfer paths (including error paths)?
│           │           │
│           │           ├── yes ──> Are there as-contract transfers?
│           │           │           │
│           │           │           ├── yes ──> Post-conditions reference contract principal
│           │           │           │           (not user principal) — verify coverage
│           │           │           │
│           │           │           └── no ──> Post-conditions adequate for transfers
│           │           │
│           │           └── no ──> FLAG: incomplete post-condition coverage
│           │
│           └── no ──> FLAG: allow mode permits hidden transfers
│
└── no ──> Post-conditions not applicable for this transaction
           BUT: check for state changes that post-conditions CANNOT protect
           │
           └── Does the transaction call external contracts?
               │
               ├── yes ──> FLAG: external contracts can modify state
               │           invisibly — need contract-level guards
               │
               └── no ──> Lower risk (but still verify contract-level guards)
```

### Post-Condition Limitations Summary

1. Post-conditions are **transaction-level**, not **contract-level** — they are specified by the transaction sender (wallet/SDK), not by the contract itself.
2. Post-conditions only constrain **asset transfers** — they cannot detect or prevent state changes.
3. `as-contract` transfers use the **contract's principal** as the sender, not the user's — post-conditions must reference the correct principal.
4. A contract with no bugs can still be exploited through a malicious external contract whose state changes are invisible to post-conditions.
5. Post-conditions are a **necessary but insufficient** safety mechanism — contract-level authorization must be the primary defense.
