# External Payloads and Negative Tests

This reference expands checkpoints `0x001e` through `0x001f`.

## Contents

- `0x001e` Attestations, nonces, and external payload binding
- `0x001f` Negative authorization and privacy tests
- Appendix: suggested negative-test checklist

---

## 0x001e-attestations-nonces-and-external-payloads-should-be-bound-to-ledger-actions

**Description:**
Message-binding issues are common in DAML systems that consume signed off-ledger payloads, secrets, nonces, attestations, bridge messages, or backend-issued approvals. A payload is not safe merely because it is authentic; it must be fully bound to the exact on-ledger action being authorized.

**Identify:**
1. Locate signed messages, attestations, secrets, nonces, external identifiers, API-issued approvals, and decoded payloads consumed by choices.
2. Review workflows that mint, burn, unlock, release, register, or authorize state transitions based on off-ledger artifacts.
3. Identify all fields copied from the external payload into ledger action parameters, including recipient, amount, instrument, object id, domain, provider, nonce, and workflow context.

**Analyze:**
1. Determine what exact ledger action the payload is supposed to authorize.
2. Verify that every security-critical field in the payload is checked against the exact contract, controller, recipient, amount, instrument, domain, nonce, and context used by the ledger action.
3. Check whether freshness, replay protection, and one-time use are actually enforced on-ledger or only assumed from backend behavior.
4. If secrets or one-time tokens are stored on-ledger, review whether the raw secret is exposed to more stakeholders than necessary and whether hashing or off-ledger storage would better preserve least disclosure.

**Remediation:**
1. Bind every external artifact to the specific ledger action it authorizes.
2. Enforce replay protection and freshness on-ledger wherever possible.
3. Treat backend-only one-time-use assumptions as trust-boundary findings unless the ledger verifies them.
4. Prefer hashed or off-ledger handling for preparatory authentication secrets when the ledger only needs the final governance-grade result.

**Related:** `0x0003` (credential/permit scoping), `0x0004` (off-chain trust boundaries)

---

## 0x001f-negative-authorization-and-privacy-cases-should-be-covered-by-daml-script

**Description:**
Audit confidence is much higher when the codebase includes executable proofs that unauthorized actions fail and invisible contracts remain invisible. Security-critical DAML systems should have negative-path tests, not just happy-path scripts.

**Identify:**
1. Locate `Daml.Script`, `submitMustFail`, scenario-style tests, and integration tests around sensitive workflows.
2. Identify the workflows that carry the highest authorization, privacy, key-consistency, request-lifecycle, and settlement risk.
3. Review whether tests cover only expected success paths or also prove forbidden paths remain forbidden.

**Analyze:**
1. Determine which negative properties matter most: unauthorized exercise, invisible contracts staying invisible, stale references being rejected, duplicate claims failing, expired rights failing, and wrong-party key operations failing when key operations are supported and used in the target version.
2. Verify whether the test suite covers stale referenced contracts, out-of-band consumption of later-used `ContractId`s, mismatched metadata versus referenced state, nested-exercise authorization failures, and privacy expectations.
3. Check whether missing tests would let ordinary misuse paths ship unnoticed because the model "seems right" in review but has never been exercised adversarially.
4. Add concurrency-shaped negative tests where the workflow depends on sequential processing, ordering, or mutable parent state. Many Canton issues only appear when two valid requests are in flight at once.

**Remediation:**
1. Require negative tests for the highest-risk authorization and privacy boundaries.
2. Add stale-reference, expiry, duplicate-claim, and wrong-controller tests for every critical queue or settlement workflow.
3. Treat missing negative tests on sensitive flows as an audit gap even when no exploit is immediately proven.

**Related:** `0x0000`--`0x0009` (authorization and visibility), `0x0018` (double-claim)

---

## Appendix: Suggested Negative-Test Checklist

This checklist maps to the most common real-world DAML exploit paths. Use it to assess test coverage and to scope PoC generation.

1. Unauthorized party attempts every sensitive choice.
2. If key operations are supported and used, a non-stakeholder attempts `fetchByKey`, `lookupByKey`, or `exerciseByKey`.
3. Expired invite, approval, or claim is exercised after time passes.
4. Duplicate claim or join is attempted against the same accepted object.
5. Caller supplies the wrong `ContractId` with right-looking business fields.
6. Referenced child contract is consumed out of band before the parent later uses it.
7. Nested exercise is attempted with a party configuration that makes the outer choice authorized but the inner choice unauthorized.
8. Observer and interface paths are checked for unintended disclosure.
9. Backend-issued nonce, attestation, or secret is replayed in a second workflow.
10. Two valid confirmations or requests for the same account are processed out of order.
11. A governance or queue action is voted on using one amount, then executed after the underlying parent balance or state has changed.
12. Membership or threshold is changed in one step, and the dependent invariant is rechecked in the next step.
13. A stale proposal or onboarding artifact is left live past expiry and then accepted or executed.
