# Clarity Attack Patterns Reference

This document describes 6 attack patterns specific to Clarity smart contracts on the Stacks blockchain. Each pattern includes a description, real-world incident reference (where applicable), vulnerable code pattern, detection guidance, and secure mitigation.

---

## 1. tx-sender Confusion Attack

### Description

When Contract A calls Contract B via `(contract-call? ...)`, `tx-sender` inside Contract B still refers to the original transaction signer — not Contract A. A malicious intermediary contract can trick users into calling it, then relay calls to a target contract where `tx-sender` resolves to the victim. If the target uses `tx-sender` for authorization, the intermediary inherits the victim's identity.

### Real-World Incident

Charisma (Sep 2024, 183k STX) — intermediary contract leveraged tx-sender identity propagation to perform unauthorized token operations.

### Vulnerable Pattern

```clarity
;; Target contract — VULNERABLE
;; Uses tx-sender for authorization in a function callable by other contracts
(define-public (withdraw (amount uint))
  (begin
    (asserts! (is-eq tx-sender (var-get owner)) (err u401))
    (stx-transfer? amount (as-contract tx-sender) tx-sender)
  )
)
```

```clarity
;; Malicious intermediary contract
;; User calls this contract, tx-sender propagates to target
(define-public (attack)
  (begin
    ;; tx-sender here is the victim who called this function
    ;; When we call the target, tx-sender inside target is STILL the victim
    (contract-call? .target-contract withdraw u1000000)
  )
)
```

### Detection Guidance

1. Search for `tx-sender` in `(asserts! ...)` guards within public functions.
2. Check if those public functions are callable via `(contract-call? ...)` from external contracts.
3. If a public function uses `tx-sender` for authorization AND can be called by other contracts, flag it.

### Mitigation

```clarity
;; Secure pattern — uses contract-caller for authorization
(define-public (withdraw (amount uint))
  (begin
    ;; contract-caller identifies the IMMEDIATE caller, not the original signer
    (asserts! (is-eq contract-caller (var-get owner)) (err u401))
    (stx-transfer? amount (as-contract tx-sender) contract-caller)
  )
)
```

---

## 2. as-contract Principal Elevation

### Description

`(as-contract ...)` switches `tx-sender` and `contract-caller` to the contract's own principal. If an attacker can reach an `as-contract` block through an unintended code path (error branch, unguarded conditional), operations execute with the contract's identity — enabling transfers of the contract's own held assets.

### Real-World Incident

Charisma (Sep 2024, 183k STX) — an error handling path retained `as-contract` context, allowing the attacker to execute token transfers as the contract principal, draining contract-held STX.

### Vulnerable Pattern

```clarity
;; VULNERABLE — as-contract reachable through error path
(define-public (process-action (action-id uint))
  (let ((action-data (unwrap! (map-get? actions action-id) (err u404))))
    (if (get is-approved action-data)
      ;; Intended path: execute approved action as contract
      (as-contract
        (stx-transfer? (get amount action-data) tx-sender (get recipient action-data))
      )
      ;; Error path: still inside as-contract scope if nesting is wrong
      ;; Or: attacker forces this branch but subsequent code uses as-contract
      (begin
        (print "action not approved")
        ;; Bug: as-contract used here without re-checking authorization
        (as-contract
          (stx-transfer? u100 tx-sender (get recipient action-data))
        )
      )
    )
  )
)
```

### Detection Guidance

1. Find all `(as-contract ...)` blocks in the contract.
2. Trace every code path that reaches each `as-contract` block — including error branches, `match` arms, and conditional fallbacks.
3. Verify that every path entering `as-contract` has passed all required authorization checks.
4. Check for nested `as-contract` calls where outer error handling may expose inner privileged operations.

### Mitigation

```clarity
;; Secure pattern — authorization completed before as-contract, minimal scope
(define-public (process-action (action-id uint))
  (let ((action-data (unwrap! (map-get? actions action-id) (err u404))))
    ;; Authorization check BEFORE any as-contract block
    (asserts! (get is-approved action-data) (err u403))
    (asserts! (is-eq contract-caller (var-get admin)) (err u401))
    ;; as-contract with narrowest possible scope
    (as-contract
      (stx-transfer? (get amount action-data) tx-sender (get recipient action-data))
    )
  )
)
```

---

## 3. List Duplication / Collateral Inflation

### Description

Clarity lists do not enforce element uniqueness. When a function iterates over a list parameter and accumulates values (collateral, rewards, votes), duplicate entries cause the same item to be counted multiple times. An attacker submits a list with repeated entries to inflate the accumulated value.

### Real-World Incident

Zest Protocol (Apr 2024, 322k STX) — duplicate entries in a collateral asset list inflated collateral value, allowing the attacker to borrow more than their actual collateral warranted.

### Vulnerable Pattern

```clarity
;; VULNERABLE — no uniqueness validation on asset list
(define-public (calculate-collateral (assets (list 10 uint)))
  (let (
    (total (fold + (map get-asset-value assets) u0))
  )
    ;; attacker submits: (list u1 u1 u1 u1 u1) — same asset counted 5x
    (ok total)
  )
)

(define-read-only (get-asset-value (asset-id uint))
  (default-to u0 (get value (map-get? asset-values { id: asset-id })))
)
```

### Detection Guidance

1. Find public functions with `(list ...)` parameters.
2. Check if the function uses `(fold ...)` or `(map ...)` to accumulate values from the list.
3. Verify whether the accumulation is idempotent (duplicates harmless) or cumulative (duplicates exploitable).
4. Check for any deduplication logic before the accumulation step.

### Mitigation

```clarity
;; Secure pattern — validate uniqueness using a fold-based tracker
(define-public (calculate-collateral (assets (list 10 uint)))
  (let (
    ;; First pass: check uniqueness
    (uniqueness-check (fold check-unique assets { seen: (list), valid: true }))
  )
    (asserts! (get valid uniqueness-check) (err u400))
    ;; Second pass: safe to accumulate
    (ok (fold + (map get-asset-value assets) u0))
  )
)

(define-private (check-unique (item uint) (state { seen: (list 10 uint), valid: bool }))
  (if (is-some (index-of (get seen state) item))
    ;; Duplicate found
    (merge state { valid: false })
    ;; New item, add to seen list
    (merge state { seen: (unwrap-panic (as-max-len? (append (get seen state) item) u10)) })
  )
)
```

---

## 4. NFT Honey-Pot via Commission Contract

### Description

NFT marketplace listings often use commission contracts — external contracts called during a sale to handle fees or royalties. Post-conditions can protect against unexpected asset transfers, but they cannot detect or prevent state changes (map updates, variable changes). A malicious commission contract can modify state that sets up a future exploit — for example, changing the listing price of another NFT, modifying ownership records, or altering fee percentages — all invisible to the buyer's post-conditions.

### Real-World Incident

No single high-profile incident, but this pattern is a known structural weakness in Stacks NFT marketplace designs identified by multiple security researchers (CertIK, CoinFabrik).

### Vulnerable Pattern

```clarity
;; Marketplace contract — calls commission contract during sale
(define-public (buy-nft (nft-id uint) (commission-contract <commission-trait>))
  (let (
    (listing (unwrap! (map-get? listings { id: nft-id }) (err u404)))
    (price (get price listing))
    (seller (get seller listing))
  )
    ;; Transfer payment
    (try! (stx-transfer? price tx-sender seller))
    ;; Transfer NFT
    (try! (nft-transfer? my-nft nft-id seller tx-sender))
    ;; Call commission — user-supplied contract!
    ;; Post-conditions catch unexpected STX/FT/NFT transfers
    ;; But state changes in commission-contract are INVISIBLE
    (try! (contract-call? commission-contract pay nft-id price))
    (ok true)
  )
)
```

```clarity
;; Malicious commission contract
(define-public (pay (nft-id uint) (price uint))
  (begin
    ;; This state change is invisible to post-conditions!
    ;; Modify another listing's price to u0 so attacker can buy it for free later
    (map-set listings { id: u42 } { price: u0, seller: 'ST_VICTIM })
    (ok true)
  )
)
```

### Detection Guidance

1. Find marketplace or protocol functions that call external/user-supplied contracts.
2. Check if those external contracts can modify state in the calling contract or shared state.
3. Verify whether the calling contract validates the external contract against a whitelist.
4. Assess what state changes the external contract can make that post-conditions would not catch.

### Mitigation

```clarity
;; Secure pattern — validate commission contract against whitelist
(define-data-var approved-commission principal 'ST_TRUSTED_COMMISSION)

(define-public (buy-nft (nft-id uint) (commission-contract <commission-trait>))
  (let (
    (listing (unwrap! (map-get? listings { id: nft-id }) (err u404)))
  )
    ;; Validate commission contract
    (asserts! (is-eq (contract-of commission-contract) (var-get approved-commission)) (err u403))
    ;; ... proceed with sale
    (try! (contract-call? commission-contract pay nft-id (get price listing)))
    (ok true)
  )
)
```

---

## 5. Unprotected ft-transfer? Token Theft

### Description

`(ft-transfer? token amount sender recipient)` accepts an explicit `sender` parameter but does **not** verify the caller is authorized to transfer from that sender. Unlike `(stx-transfer? ...)` which requires `tx-sender` to equal the sender, `ft-transfer?` executes for any caller-specified sender. A public function that passes a user-supplied principal as the sender without authorization checking allows any caller to drain any user's tokens.

### Real-World Incident

No single named incident, but this is the #1 Clarity vulnerability pattern identified by CertIK and multiple auditors. The Arkadiko Swap exploit (Oct 2021, ~$1.5M) involved related LP token validation failures.

### Vulnerable Pattern

```clarity
;; VULNERABLE — sender is a function parameter without authorization check
(define-public (transfer (amount uint) (sender principal) (recipient principal))
  (begin
    ;; Missing: (asserts! (is-eq tx-sender sender) (err u401))
    (ft-transfer? my-token amount sender recipient)
  )
)
```

### Detection Guidance

1. Find all `(ft-transfer? ...)` and `(nft-transfer? ...)` calls.
2. Check if the `sender` argument comes from a function parameter.
3. Verify an explicit `(asserts! (is-eq tx-sender sender) ...)` or equivalent check exists before the transfer.
4. Check for SIP-010 compliance: the `transfer` function MUST verify sender authorization.

### Mitigation

```clarity
;; Secure SIP-010 compliant transfer
(define-public (transfer (amount uint) (sender principal) (recipient principal) (memo (optional (buff 34))))
  (begin
    ;; REQUIRED: verify caller is the sender
    (asserts! (is-eq tx-sender sender) (err u401))
    (try! (ft-transfer? my-token amount sender recipient))
    (match memo to-print (print to-print) 0x)
    (ok true)
  )
)
```

---

## 6. Trait Reference Redirection

### Description

Clarity allows passing trait references as function parameters. A function accepting `(token <ft-trait>)` can be called with any contract that implements `<ft-trait>`. A malicious contract can implement the trait with adversarial logic: `get-balance` returns inflated values, `transfer` redirects funds, or read-only functions return false data to manipulate pricing or collateral calculations.

### Real-World Incident

ALEX Protocol (Jun 2025, $8.3M) — self-listing verification logic vulnerability allowed an attacker to use a malicious token contract that passed validation checks, leading to fund extraction. Trait reference validation was insufficient.

### Vulnerable Pattern

```clarity
;; VULNERABLE — accepts any contract implementing ft-trait
(define-public (deposit-collateral (token <ft-trait>) (amount uint))
  (begin
    ;; No validation that 'token' is an approved token contract
    ;; Attacker passes a malicious contract:
    ;;   - get-balance returns inflated value
    ;;   - transfer does nothing (keeps attacker's funds)
    (try! (contract-call? token transfer amount tx-sender (as-contract tx-sender) none))
    ;; Protocol records collateral based on 'amount' parameter
    ;; But the malicious token's transfer was a no-op
    (map-set collateral { user: tx-sender } { amount: (+ amount (get-collateral tx-sender)) })
    (ok true)
  )
)
```

### Detection Guidance

1. Find public functions accepting trait reference parameters.
2. Check whether the trait reference is validated against a whitelist of approved contracts.
3. Assess what happens if a malicious implementation returns unexpected values from read-only trait functions.
4. Verify whether the function checks actual balance changes (post-transfer balance delta) rather than trusting the `amount` parameter.

### Mitigation

```clarity
;; Secure pattern — whitelist validation for trait references
(define-map approved-tokens principal bool)

(define-public (deposit-collateral (token <ft-trait>) (amount uint))
  (let (
    (token-contract (contract-of token))
    (balance-before (unwrap-panic (contract-call? token get-balance (as-contract tx-sender))))
  )
    ;; Validate against whitelist
    (asserts! (default-to false (map-get? approved-tokens token-contract)) (err u403))
    ;; Execute transfer
    (try! (contract-call? token transfer amount tx-sender (as-contract tx-sender) none))
    ;; Verify actual balance change (defense-in-depth)
    (let ((balance-after (unwrap-panic (contract-call? token get-balance (as-contract tx-sender)))))
      (asserts! (>= (- balance-after balance-before) amount) (err u402))
      (map-set collateral { user: tx-sender } { amount: (+ amount (get-collateral tx-sender)) })
      (ok true)
    )
  )
)
```
