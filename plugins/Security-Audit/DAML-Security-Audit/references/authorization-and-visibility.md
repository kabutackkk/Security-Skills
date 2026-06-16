# Authorization, Visibility, and Trust Boundaries

This reference expands checkpoints `0x0000` through `0x0009`.

## Contents

- `0x0000` Obligated parties and business consent
- `0x0001` Choice controllers
- `0x0002` Privileged role transfer
- `0x0003` Credentials, permits, and delegation
- `0x0004` Off-chain trust boundaries
- `0x0005` Custody and signatory model
- `0x0006` Locks, mandates, and preapprovals
- `0x0007` Observer sets
- `0x0008` Choice visibility and divulgence
- `0x0009` Interfaces and views

---

## 0x0000-obligated-parties-should-be-signatories

**Description:**
Any party that becomes legally, economically, or operationally bound at contract creation should either be a signatory on the created contract or should have already provided a clearly scoped accept step bound to the same object and terms. A common DAML failure mode is confusing ledger authorization with business consent: the transaction may be authorized as a party, and the created template may name that party as a signatory, while the exact business terms are still too weakly bound to what that party actually approved.

**Identify:**
1. Locate templates that create obligations, lock assets, establish custody, create debt, create recurring duties, or place a party into a governance or operational role.
2. Review `template` headers, `signatory` clauses, and every `create` or `createAndExercise` path that can instantiate those templates.
3. Pay special attention to nested create flows where a caller supplies party fields or payload records that are turned into a binding downstream contract.

**Analyze:**
1. Identify every party that becomes committed, economically exposed, loses optionality, or gains mandatory future actions when the contract is created.
2. Verify that each such party is a signatory on the binding contract or that the workflow includes a prior explicit consent step scoped to the same parties, object identity, and economic parameters.
3. Check whether a party is only mentioned in payload fields, observer sets, downstream controller sets, or interface views — none of which is equivalent to consenting to the create.
4. Distinguish "the ledger saw Alice authorize this transaction" from "Alice approved this exact amount, counterparty, asset, request id, and workflow instance." Broad delegation, stale mutable state, or poorly bound finalization can satisfy the former while failing the latter.
5. The exploit path is: a creator or operator finalizes a binding contract with authority that is technically valid on-ledger, but the exact terms were never directly approved by the bound party in a properly scoped step.

**Remediation:**
1. Require obligated parties to be signatories on the binding contract unless there is an earlier explicit accept step.
2. Bind any earlier accept step to the exact contract instance, amount, counterparties, and context later created.
3. Do not treat "the created template lists Alice as a signatory" or "the transaction was authorized as Alice" as sufficient proof of business consent by itself. Verify that Alice either approved the exact terms at the final binding step or previously accepted the same object and terms in a step that is semantically bound to the later create.

**Example (authorization-consistent schematic pseudocode):**
These examples are simplified, but they are structured to match DAML's basic authorization model. The point is to show whether business terms are bound tightly enough to prior consent, not to provide production-ready code.

Sufficient proof of business consent:
Alice first exercises an `AcceptTransfer` or `ApproveLoan` choice that she controls, and that acceptance records the exact amount, asset, counterparty, and request id later used by the binding `create`. A later operator or counterparty create is acceptable if it is mechanically bound to that accepted object and cannot change those terms.

Insufficient proof of business consent:
The system can show valid ledger authorization for Alice, but the exact terms still come from mutable state or delegated operator input that Alice did not approve in a properly bound step. Alice's name appearing in the created template, or her authority being used for the transaction, is not by itself proof that she agreed to this exact obligation.

Weak pattern:

```daml
template Quote
  with
    operator : Party
    alice : Party
    requestId : Text
    qty : Decimal
  where
    signatory operator
    observer alice

    choice Replace : ContractId Quote
      with newQty : Decimal
      controller operator
      do
        create this with
          qty = newQty

template TradeRequest
  with
    operator : Party
    alice : Party
    requestId : Text
  where
    signatory operator
    observer alice

    choice Approve : ContractId Approval
      controller alice
      do
        create Approval with
          operator = operator
          alice = alice
          requestId = requestId

template Approval
  with
    operator : Party
    alice : Party
    requestId : Text
  where
    signatory operator, alice

    choice Finalize : ContractId Trade
      with
        quoteCid : ContractId Quote
      controller operator
      do
        quote <- fetch quoteCid
        assert (quote.requestId == requestId)
        create Trade with
          buyer = alice
          seller = operator
          quantity = quote.qty

template Trade
  with
    buyer : Party
    seller : Party
    quantity : Decimal
  where
    signatory buyer, seller
```

Here Alice signs an `Approval` that binds only `requestId`. Because `Approval` is itself signed by both Alice and the operator, the operator can later exercise `Finalize` and create `Trade` using any live `Quote` whose `requestId` matches. If the operator first exercises `Replace` to create a successor `Quote` with the same `requestId` but a different `qty`, the later `Trade` is still technically authorized on-ledger, but Alice never approved that exact quantity in a bound artifact.

Strong pattern:

```daml
template Quote
  with
    operator : Party
    alice : Party
    requestId : Text
    qty : Decimal
  where
    signatory operator
    observer alice

    choice Replace : ContractId Quote
      with newQty : Decimal
      controller operator
      do
        create this with
          qty = newQty

template TradeRequest
  with
    operator : Party
    alice : Party
    quoteCid : ContractId Quote
  where
    signatory operator
    observer alice

    choice Approve : ContractId ApprovedQuote
      controller alice
      do
        quote <- fetch quoteCid
        create ApprovedQuote with
          operator = operator
          alice = alice
          quoteCid = quoteCid
          requestId = quote.requestId
          qty = quote.qty

template ApprovedQuote
  with
    operator : Party
    alice : Party
    quoteCid : ContractId Quote
    requestId : Text
    qty : Decimal
  where
    signatory operator, alice

    choice Finalize : ContractId Trade
      controller operator
      do
        quote <- fetch quoteCid
        assert (quote.requestId == requestId)
        assert (quote.qty == qty)
        create Trade with
          buyer = alice
          seller = operator
          quantity = qty

template Trade
  with
    buyer : Party
    seller : Party
    quantity : Decimal
  where
    signatory buyer, seller
```

Here Alice's `Approve` choice binds consent to the exact `quoteCid` and snapshots the approved `qty`. If the operator later replaces the quote with a successor contract, `Finalize` fails because the old `quoteCid` is no longer live. If the original quote remains live but the operator tries to rely on mismatched fields, the explicit equality checks fail. The operator therefore cannot turn Alice's earlier approval into consent for a different quantity without obtaining a fresh approval.

**Related:** `0x0005` (custody model mismatch), `0x0002` (role transfer handshakes)

---

## 0x0001-choice-controllers-should-be-visible-and-business-authorized

**Description:**
Choice controllers define who may transition ledger state. DAML authorization is local to each exercise, so a choice body must not assume that authority from an earlier create, proposal, or surrounding workflow is inherited automatically.

**Identify:**
1. Review every `choice` declaration, especially sensitive settlement, approval, cancellation, withdrawal, transfer, and governance choices.
2. Locate static and dynamic `controller` clauses, including controllers derived from contract fields, fetched data, or choice arguments.
3. Trace nested `exercise` and `exerciseByKey` flows where downstream authorization depends on data from a referenced contract.
4. In multi-leg or helper-driven workflows, list every downstream child-contract action separately, including main legs, fee legs, change legs, optional cleanup legs, refunds, and auxiliary allocations or receipts.

**Analyze:**
1. Recompute the controller set at the exact point of exercise for each sensitive choice.
2. Verify that each controller can legitimately see the contract and that the controller set matches the business approvals required for the transition.
3. Check whether a syntactically authorized actor can still be the wrong business actor because the choice relies on stale assumptions from an earlier step rather than re-establishing authority locally.
4. For nested exercises, compute whether the outer workflow's intended signatories/controllers/readers can actually satisfy every downstream child-contract controller set. Do this leg by leg; a valid main leg does not prove that fee or cleanup legs are also executable.
5. The exploit path is: a party satisfying the literal `controller` clause but lacking intended business authority invokes a sensitive choice, or a parent workflow reaches a downstream child-contract exercise whose true controller set is not covered by the parent authorization model.

**Remediation:**
1. Validate business role, visibility, and state assumptions inside the choice that performs the transition.
2. Treat dynamic controller derivation as a security surface, not just a typing exercise.
3. Audit nested exercises separately; the outer controller set does not automatically justify the inner one.
4. Build an authorization matrix for multi-leg flows and confirm that every auxiliary leg that must succeed under the advertised workflow can be exercised without undocumented extra authorizers.

**Related:** `0x0004` (off-chain trust boundaries), `0x000e` (role assignment at execution)

---

## 0x0002-privileged-role-transfers-should-use-safe-handshake-patterns

**Description:**
Admin, operator, owner, delegate, and custodian changes are high-impact transitions. Single-step reassignment can permanently redirect control, create lockout, or grant power to the wrong party with no recovery path.

**Identify:**
1. Locate choices that assign, transfer, delegate, revoke, or escalate roles such as admin, owner, operator, registrar, issuer, custodian, or governance member.
2. Review templates that store pending role transfers, role offers, handoff requests, or replacement authorities.
3. Check for emergency recovery, cancellation, revocation, and timeout paths around the transfer.

**Analyze:**
1. Verify whether the incoming privileged party must explicitly accept the role before the handoff becomes live.
2. Confirm that the outgoing privileged party retains an appropriate cancellation or recovery path until acceptance is complete.
3. Review scope and duration for delegated authority; broad or permanent delegation often needs a stronger handshake than an operational convenience role.
4. Check whether the protocol can revoke or rotate the privileged role later. A safe onboarding path paired with no governance-grade revocation path is still a lifecycle weakness.
5. The exploit path is: the current privileged party unilaterally points a high-impact role at a malicious, unreachable, or mistyped replacement, causing privilege theft or governance lockout with no recovery.

**Remediation:**
1. Prefer propose-and-accept handshakes for privileged role transfer.
2. Add expiry, cancellation, and recovery for pending transfers.
3. Review whether the role transfer should be immediate, staged, or revocable based on blast radius.

**Related:** `0x0000` (obligated parties as signatories), `0x0003` (delegation scoping)

---

## 0x0003-credential-permit-and-delegation-patterns-should-be-scoped-revocable-and-action-bound

**Description:**
DAML systems often model permission through permit, token, approval, proxy, or delegation templates rather than making every actor a signatory on the target contract. This is powerful, but dangerous when the credential is too broad, replayable, non-revocable, or weakly bound to the action being authorized.

**Identify:**
1. Locate credential, permit, delegation, approval, authority-grant, proxy, or mandate templates.
2. Find every place where a fetched contract is treated as proof that one party may act for another.
3. Review grant, revoke, accept, proxy-execute, and consume-or-reuse flows for those credentials.

**Analyze:**
1. Verify which actions the credential authorizes and whether it is scoped by party, asset, amount, time window, workflow type, and object identity.
2. Check whether the grant can be revoked or naturally expires, and whether the workflow distinguishes single-use from reusable authority.
3. Determine whether the same credential can be replayed in another context, reused after revocation, or combined with caller-controlled arguments to authorize more than intended.
4. Check whether value or rewards are attributed at claim time using the holder's current credential set rather than being snapshotted to the intended beneficiary when the right is created.

**Remediation:**
1. Bind delegation artifacts to action type, subject, scope, and freshness.
2. Add revocation, expiry, and one-shot consumption where appropriate.
3. Revalidate the authorized context at the exact exercise that consumes the credential.
4. Where a right should belong to the actor who performed the service, snapshot that beneficiary at creation rather than resolving it later from mutable live credentials.

**Related:** `0x0006` (locks and mandates), `0x001e` (external attestation binding)

---

## 0x0004-privileged-roles-and-offchain-trust-boundaries-should-be-explicitly-audited

**Description:**
Many DAML/Canton systems rely on operators, APIs, automation, registrars, attesters, sequencers, or backend services to enforce safety properties that the ledger itself does not enforce. Those assumptions must be treated as a primary audit surface, not as implementation detail.

**Identify:**
1. Locate provider, registrar, attester, backend, KMS, wallet, or automation roles whose honest behavior is required for the workflow to remain safe.
2. Review comments, docs, and code paths that say a risky state transition is prevented operationally, by command deduplication, by one service instance, or by API-side checks.
3. Inspect backend and automation code that prepares disclosed contracts, chooses command ids, retries requests, or decides which choices to exercise.

**Analyze:**
1. Separate guarantees enforced on-ledger from those merely assumed from backend logic, operational process, or deployment topology.
2. Determine whether compromise, downtime, collusion, or race conditions in the privileged component could cause fund loss, false progression, censorship, replay, or liveness failure.
3. Check whether the off-ledger layer is the only thing preventing duplicate requests, wrong-target selection, stale claims, or unsafe sequencing.
4. Treat backend-enforced sequentialization, ordering guarantees, and "only one active workflow per account" rules as explicit trust assumptions deserving the same scrutiny as registrar or attestor honesty.

**Remediation:**
1. Record every safety property that depends on an off-ledger actor and treat it as a first-class finding candidate.
2. Prefer ledger-enforced checks over API-only or operator-only safeguards.
3. Where off-ledger trust is intentional, document the blast radius and failure mode clearly.

**Related:** `0x000b` (delegated uniqueness), `0x001e` (external payload binding)

---

## 0x0005-holding-custody-and-signatory-model-should-match-the-intended-trust-model

**Description:**
Payment, custody, and token systems often represent balances as holdings controlled by owners, issuers, providers, lockers, or custodians. A mismatch between the actual signatory/controller model and the documented trust split can let one side seize, freeze, redirect, or block movement of funds more broadly than intended.

**Identify:**
1. Locate holding, custody, lock, wallet, escrow, reserve, or account-like templates.
2. Identify roles such as issuer, owner, provider, custodian, registrar, locker, or service operator and how they participate in signatory and controller sets.
3. Review normal transfer, mint, burn, lock, unlock, recovery, and exceptional-archive flows.
4. Check whether permission to mint or burn is represented only indirectly through account possession or workflow position, rather than through explicit credentials or role-bearing contracts.

**Analyze:**
1. Determine the intended custody model from code comments, docs, and surrounding workflow assumptions.
2. Compare that intent with the actual signatories, observers, controllers, and archive paths in every reachable state.
3. Check whether any actor has stronger unilateral power than intended, or whether legitimate movement requires unsafe off-ledger coordination because the ledger model is too restrictive.

**Remediation:**
1. Audit the custody model as a ledger-enforced power model, not just as documentation.
2. Verify exceptional flows against the same trust split as ordinary transfers.
3. Flag any mismatch between documented custody and actual unilateral authority.
4. Prefer explicit issuer or burner credentials when mint or burn authority is meant to be role-gated rather than merely workflow-gated.

**Related:** `0x0000` (obligated parties), `0x0006` (lock/preapproval boundaries)

---

## 0x0006-locks-preapprovals-and-recurring-mandates-should-be-bounded-revocable-and-safely-releasable

**Description:**
Locks, transfer preapprovals, and recurring mandates behave like standing rights. They become dangerous when scope, expiry, revocation, release, or unwind logic is ambiguous or missing.

**Identify:**
1. Locate `Lock`, `TimeLock`, holding-lock, preapproval, mandate, subscription, or recurring-payment templates.
2. Review `collect`, `send`, `renew`, `revoke`, `expire`, `release`, `unlock`, and timeout choices.
3. Check whether any right is reusable through `nonconsuming` choices or through successor contracts that preserve authority.

**Analyze:**
1. Determine what authority the lock, preapproval, or mandate grants, to whom, over which assets, and for how long.
2. Verify whether amount limits, asset scope, workflow scope, duration, renewal, timeout, and revocation are explicit and enforced on-ledger.
3. Check whether assets or permissions can become trapped indefinitely if one counterparty disappears or if the off-ledger service stops acting.

**Remediation:**
1. Bound rights by asset, amount, action, and time.
2. Provide clear revoke, expire, and safe-release paths.
3. Confirm that reusable choices match actual business intent.

**Related:** `0x0003` (delegation scoping), `0x0014` (nonconsuming choice mode)

---

## 0x0007-observer-sets-should-follow-need-to-know

**Description:**
Observers become stakeholders and gain visibility into contract contents and lifecycle. Over-broad observer sets are direct privacy leaks in DAML, especially when observer lists are dynamic or influenced by user-controlled inputs.

**Identify:**
1. Review all `observer` clauses, dynamic observer lists, and helper functions that compute observer membership.
2. Locate regulator, admin, service-account, analytics, or convenience observers added for operational reasons.
3. Check whether observers are inherited from reference contracts or caller-supplied lists.

**Analyze:**
1. Identify every source of observer membership and why each observer needs to know the contract.
2. Verify that user-controlled data cannot expand the visibility set beyond the business requirement.
3. Determine whether excess visibility reveals balances, positions, pricing, identities, workflow state, or private strategy to parties that should not learn them.

**Remediation:**
1. Keep observers to strict need-to-know.
2. Move low-sensitivity public metadata into separate reference contracts where possible.
3. Audit dynamic observer derivation with the same rigor as controller derivation.

**Related:** `0x0008` (divulgence), `0x0009` (interface view leaks), `0x001c` (fan-out disclosure growth)

---

## 0x0008-choice-visibility-and-divulgence-should-be-explicitly-reviewed

**Description:**
Privacy in DAML depends not only on contract stakeholders but also on transaction structure. A legitimate exercise can still divulge contract existence, branches, or nested contract data to parties who were not intended to learn them.

**Identify:**
1. Locate choices that fetch, exercise, archive, or create contracts with different stakeholder sets from the root contract.
2. Review flows with explicit choice observers, nested exercises, and helper choices that traverse multiple contract graphs.
3. Pay attention to protocols where business sensitivity comes from the existence or timing of an exercise, not just from the payload contents.

**Analyze:**
1. Compute the effective visibility graph for each sensitive exercise, including choice observers and nested actions.
2. Determine whether any referenced contracts may be divulged or whether new parties learn about contract existence, branch selection, or economic consequences through the exercise path.
3. Check whether the protocol assumes more privacy than Canton and DAML actually provide at transaction time.

**Remediation:**
1. Review visibility of each sensitive exercise, not just template stakeholder sets.
2. Audit nested actions across contract boundaries for divulgence side effects.
3. Flag any protocol that relies on implicit privacy assumptions around exercise paths.

**Related:** `0x0007` (observer sets), `0x0009` (interface views)

---

## 0x0009-interfaces-and-views-should-not-hide-authorization-or-leak-data

**Description:**
Interfaces and views are powerful abstraction tools, but they can hide template-specific authorization assumptions or expose more data than intended through generalized views. Auditors should not stop at the interface boundary.

**Identify:**
1. Locate `interface`, `viewtype`, `toInterface`, interface instances, and interface-mediated choices.
2. Find code that consumes interface views rather than concrete templates, especially when those views drive routing, authorization, or settlement decisions.
3. Review any shared interface intended to abstract over multiple concrete templates with different security properties.

**Analyze:**
1. Identify what data the interface view reveals and whether consumers need all of it.
2. Compare interface-level assumptions with concrete-template signatories, observers, choices, and invariants hidden behind the abstraction.
3. Check whether callers can drive logic safely across all implementing templates, or whether template-specific constraints are lost when viewed through the interface.

**Remediation:**
1. Audit template-level behavior behind every interface path, not just the exposed view.
2. Minimize view contents to the data truly required by consumers.
3. Treat interface abstraction as a possible source of hidden authorization and privacy drift.

**Related:** `0x0007` (observer sets), `0x0008` (divulgence)
