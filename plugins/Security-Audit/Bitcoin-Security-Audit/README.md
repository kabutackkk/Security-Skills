# Bitcoin Security Audit

Structured security audit checklists for the **Bitcoin ecosystem** — covering Clarity smart contracts, PSBT signing flows, Ordinals/BRC-20/Runes marketplaces, BTC staking protocols, and Lightning Network dApps. Each skill walks an auditor through a checklist of numbered checkpoints grounded in real-world incidents and documented attack patterns. Every checkpoint follows a four-stage reasoning structure — Identify, Analyze, Exploitability, Check — so that findings are evidence-grounded rather than speculative.

## Skills

The five skills cover distinct Bitcoin-ecosystem audit domains. A dispatcher (`skills/SKILL.md`) routes requests to the correct skill by matching keywords in the user's prompt; it never auto-executes and always waits for user confirmation. A project may match multiple skills — for example, an Ordinals marketplace with custom PSBT signing would trigger both the marketplace and PSBT skills.

### `/audit-clarity-general` — Clarity Smart Contract Audit

Security audit for Clarity smart contracts deployed on the Stacks blockchain.

**Coverage**:
- Authentication model: `tx-sender` vs `contract-caller` confusion, `as-contract` privilege escalation
- Token transfer authorization gaps in SIP-010, SIP-009, and SIP-013 implementations
- Post-condition blind spots that allow unintended asset movement
- Error handling and inter-contract call safety
- TypeScript SDK patterns (`@stacks/transactions`, `@stacks/connect`)

### `/audit-psbt-security` — PSBT Construction & Signing Audit

Security audit for Partially Signed Bitcoin Transaction flows (BIP-174 / BIP-370).

**Coverage**:
- Sighash misuse (`SIGHASH_NONE`, `SIGHASH_ANYONECANPAY` abuse)
- Input/output injection during multi-party signing
- UTXO verification failures and fee manipulation
- Taproot trust model confusion and key-path vs script-path risks
- MuSig2 nonce safety violations
- Finalization integrity gaps
- SDK patterns (`bitcoinjs-lib`, `@scure/btc-signer`, `tiny-secp256k1`)

### `/audit-btc-marketplace-general` — Ordinals / BRC-20 / Runes Marketplace Audit

Security audit for Bitcoin-native NFT and token marketplace implementations.

**Coverage**:
- Listing PSBT manipulation and seller-side injection
- Inscription UTXO mismanagement (cardinal/ordinal separation failures)
- Indexer trust failures and state divergence
- Front-running and snipping attacks on pending listings
- Fee manipulation and platform trust boundary violations
- SDK patterns (`bitcoinjs-lib`, ordinal indexer integrations)

### `/audit-btc-staking-general` — BTC Staking Protocol Audit

Security audit for Babylon-style Bitcoin staking protocol implementations.

**Coverage**:
- Covenant bypass vulnerabilities in pre-signed transaction schemes
- EOTS (Extractable One-Time Signature) slashing failures
- Timelock manipulation and premature unbonding
- Delegation trust boundary violations
- Reward distribution exploits and bridge/checkpoint integrity gaps
- SDK patterns (`@babylonlabs-io/btc-staking-ts`)

### `/audit-ln-dapp-general` — Lightning Network dApp Audit

Security audit for applications built on the Lightning Network.

**Coverage**:
- Preimage exposure and payment hash reuse
- Timelock misconfiguration and CLTV expiry delta errors
- HTLC state machine flaws in swap implementations
- Swap non-atomicity (submarine swaps, reverse swaps, Loop, Boltz)
- Force-close fee budget gaps and replacement cycling
- Watchtower failures and Taproot channel / PTLC weaknesses
- SDK patterns (`ln-service`, `lnrpc`, `@boltz/boltz-core`, `lnurl-pay`)

## Shared Principles

All skills in this plugin share a set of ground rules:

- **Checklist-driven.** Every audit follows numbered checkpoints (`0x0000`–`0x00XX`) with a consistent four-stage structure: Identify vulnerable code, Analyze severity, assess Exploitability with concrete attack scenarios, then Check validation steps. This makes audits reproducible and gaps visible.
- **Incident-grounded.** Each skill opens with real-world security incidents that motivate the checklist. Checkpoints reference documented attack patterns rather than hypothetical risks.
- **Evidence-required findings.** A finding is reported only when a concrete code path supports it. Absence of a common check is flagged for review, never asserted as a vulnerability on its own.
- **Scope honesty.** Each skill declares what it covers, what it does not, and where a different skill or domain-specific review is required. Skills cross-reference each other when domains overlap (e.g., the PSBT skill references the marketplace skill for listing-specific PSBT flows).
- **Actionable output.** Findings follow a strict format — Title, Code Location, Description, Scenario (with fictional actors), and Recommendation — so that developers can act on them immediately.

## Findings Output

Audit results are written to `findings.md` at the project root. Each finding includes:

1. **Title** — `{Issue} Leads To {Outcome}` (title case)
2. **Code location** — `filename-L{start}~L{end}`
3. **Description** — function purpose, issue, and impacts
4. **Scenario** — step-by-step attack using fictional actors (Alice, Bob)
5. **Recommendation** — actionable fix

---

## Example Workflow

1. Install the plugin (see installation above).
2. Invoke the skill at a Bitcoin-ecosystem codebase and describe the project — the dispatcher will recommend the matching skill(s).
3. Confirm which skill(s) to execute; multiple skills can run on the same project when domains overlap.
4. The skill walks through its checklist, producing findings in `findings.md` as issues are confirmed.
5. Review the findings, address confirmed issues, and re-run the relevant checkpoints to validate fixes.
