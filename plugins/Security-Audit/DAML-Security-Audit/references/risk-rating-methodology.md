# risk-rating-methodology

This reference adapts the OWASP risk-rating model to DAML and Canton security review. Use it to assign a consistent `Likelihood`, `Impact`, and final severity to each confirmed finding.

The goal is not fake precision. The goal is to make the rating defensible, repeatable, and grounded in how the DAML workflow actually behaves on-ledger and off-ledger.

## Contents

- Core model
- Step 1: Define the finding precisely
- Step 2: Estimate likelihood
- Step 3: Estimate impact
- Step 4: Determine final severity
- Step 5: DAML-specific rating guidance
- Step 6: Report the rating
- Suggested wording patterns
- Final rule

## Core model

Risk severity is derived from:

`Severity = Likelihood x Impact`

For DAML audits, always rate:

- the most credible threat actor under the documented trust model
- the exact reachable code path, not a theoretical anti-pattern in isolation
- the actual blast radius across parties, assets, privacy, governance, and liveness

If business documentation, design notes, or the README describe the intended workflow, use that context when selecting both likelihood and impact.

## Step 1: Define the finding precisely

Before assigning a rating, identify:

- the vulnerable template, choice, interface, key flow, or off-ledger orchestration step
- the attacker or triggering actor
- the preconditions required to reach the bug
- the concrete impact if the bug succeeds
- who is harmed: the caller, a counterparty, a privileged operator, a subset of users, or the whole protocol

Do not risk-rate unvalidated candidates.

## Step 2: Estimate likelihood for DAML/Canton

Likelihood measures how realistically the issue can be discovered and exploited in the deployed workflow.

Use the factors below informally, or score them if a more repeatable process is needed.

### A. Threat actor level

Pick the least-trusted actor that can realistically trigger the issue:

- `Low`: requires the same trusted operator, governance body, or privileged maintainer to violate its own documented duties
- `Medium`: requires an authenticated party, stakeholder, participant-local access holder, or partially privileged workflow actor
- `High`: reachable by an ordinary user, counterparty, or broadly available integration path

Guidance:

- If exploitation requires a privileged role, start with `Likelihood: Low`
- Raise above `Low` only if the privileged action is easy to trigger accidentally, can be delegated unintentionally, or can be bypassed by a less-trusted actor

### B. Reachability

Assess how directly the bug can be reached:

- `Low`: requires unusual deployment topology, impossible duplicate state under the trust model, or service misbehavior outside the intended model
- `Medium`: requires stale state, concurrency, timing, alternate submission paths, or a specific integration flow
- `High`: reachable from an ordinary happy-path choice flow or a standard API path

### C. Exploit complexity

Assess how hard exploitation is once the path is reachable:

- `Low`: requires precise timing, race orchestration, multi-step coordination, or deep DAML/Canton knowledge
- `Medium`: requires deliberate but straightforward setup
- `High`: simple to reproduce once identified

### D. Detection and existing controls

Assess how likely existing controls are to stop or expose the exploit:

- `Low`: strong on-ledger enforcement or reviewed operator checks make exploitation difficult to complete unnoticed
- `Medium`: detection exists but is operational, partial, or after-the-fact
- `High`: no meaningful prevention or review exists, or the workflow collapses multiple conflicting states into one status view

## Likelihood decision rule

Use the following practical summary:

- `Likelihood: Low`
  The issue depends on privileged roles, trusted services, or rare operational missteps, and untrusted actors cannot force it directly.
- `Likelihood: Medium`
  The issue is reachable through realistic workflow conditions such as stale requests, alternate submission paths, timing windows, or authenticated misuse.
- `Likelihood: High`
  The issue is directly reachable by normal users or counterparties with little setup and weak detection.

If the factors point in different directions, weight actor privilege and reachability most heavily.

## Step 3: Estimate impact for DAML/Canton

Impact measures the damage if the finding is successfully exploited.

Assess both technical and business consequences. When business context is available, prefer that over a purely technical reading.

### A. Asset and accounting impact

- `Low`: no asset movement, no durable accounting corruption, limited inconvenience
- `Medium`: incorrect fees, stale rights execution, localized settlement failure, trapped requests, or bounded fund impact
- `High`: theft, mint/burn mismatch, conservation failure, double claim, wrong-recipient transfer, or system-wide accounting corruption

### B. Authorization and governance impact

- `Low`: self-directed misuse with no cross-party harm
- `Medium`: unauthorized action against a counterparty or a limited privileged workflow
- `High`: privilege takeover, governance lockout, unsafe admin transfer, or durable control redirection affecting others

### C. Privacy and disclosure impact

- `Low`: minor metadata exposure with limited sensitivity
- `Medium`: unwanted disclosure of workflow relationships, balances, or party participation to unauthorized viewers
- `High`: broad exposure of sensitive transaction, account, or identity data across trust boundaries

### D. Liveness and operational impact

- `Low`: temporary inconvenience with clear recovery
- `Medium`: stuck state, replayable queue item, blocked lifecycle transition, or manual recovery burden
- `High`: protocol-wide halt, unrecoverable deadlock, stranded assets, or repeated denial of service on critical flows

## Impact decision rule

Use the highest credible impact dimension that matches the reachable scenario:

- `Impact: Low`
  The effect is local, recoverable, and does not significantly harm another party or core protocol invariant.
- `Impact: Medium`
  The effect causes material counterparty harm, workflow failure, or bounded financial or privacy damage.
- `Impact: High`
  The effect breaks asset safety, governance safety, protocol-wide liveness, or major privacy boundaries.

## Step 4: Determine final severity

Use this matrix:

| Impact \\ Likelihood | Low | Medium | High |
| --- | --- | --- | --- |
| High | Medium | High | Critical |
| Medium | Low | Medium | High |
| Low | Note | Low | Medium |

Interpretation:

- `Critical`: easily reachable, severe cross-party or protocol-wide damage
- `High`: meaningful financial, governance, privacy, or liveness harm with realistic exploitability
- `Medium`: real and reachable security weakness with bounded blast radius or meaningful preconditions
- `Low`: valid but constrained issue with limited harm or strong prerequisites
- `Note`: hardening issue, trust assumption, or minor weakness that should not be presented as a major vulnerability

## Step 5: DAML-specific rating guidance

### Privileged-role findings

If a finding requires a privileged operator, validator, sponsor, service, or governance controller, default to:

- `Likelihood: Low`

Only increase likelihood if:

- a less-trusted actor can trigger the same effect
- the privileged role can be induced into the action through a normal workflow
- the action is routine enough that accidental misuse is realistic

### Off-ledger protections

If safety depends on backend checks, automation ordering, or API-side filtering:

- keep the finding only if bypass is realistically reachable or other parties rely on that guarantee
- rate likelihood based on who can bypass or circumvent the service boundary
- do not call a same-operator self-check failure `High` likelihood by default

### Duplicate-state and weak-binding findings

Only assign meaningful severity if conflicting live state is realistically reachable under the documented trust model.

If duplicate state would require the same trusted namespace owner to violate its own duties and harm only itself, downgrade to `Low` or `Note`, or drop the candidate entirely.

### Self-harm-only paths

If the only harmed party is the same controller or operator required to exercise the vulnerable path, impact is often `Low` unless the resulting state harms counterparties, system accounting, or protocol invariants.

## Step 6: Report the rating

Every confirmed finding should explicitly state:

- `Severity`
- `Likelihood`
- `Impact`

Also include one short sentence justifying the rating in DAML terms, for example:

- why the attacker can realistically reach the choice path
- why the blast radius is local or cross-party
- why privileged-role preconditions lower likelihood

## Suggested wording patterns

- `Likelihood: Low. Exploitation requires the trusted operator's own backend path to mis-handle a one-time secret, and ordinary users cannot force that state directly.`
- `Impact: Medium. A stale request can still lock a counterparty into obsolete payment terms, but the blast radius is limited to the affected subscription workflow.`
- `Likelihood: High. Any authenticated user on the standard order-entry path can trigger the mismatch without special privileges.`
- `Impact: High. Settlement can transfer the wrong asset and break the market's core accounting invariant.`

## Final rule

Do not assign severity from intuition alone. Validate the code path first, then derive `Likelihood`, `Impact`, and severity using this DAML-adapted model.
