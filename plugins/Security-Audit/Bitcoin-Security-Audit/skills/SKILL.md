# project-type-dispatcher

| name | description |
| --- | --- |
| project-type-dispatcher | Dispatch audit skill based on project type. Determines which audit checklist to use according to project type keywords. |

## Purpose

This skill is responsible for:

1. Identifying the type of project based on keywords and context
2. Listing recommended audit skills for the user to choose from
3. Providing clear descriptions of why each skill is recommended

## When to Use This Skill

**Prompt trigger:**

User asks for security audit, vulnerability check, or contract review without specifying which audit skill to use.

## Output Format

When this skill is triggered, the agent should:

1. Analyze the project description and identify relevant keywords
2. Match keywords to applicable audit skills
3. Present a numbered list of recommended skills with:
   - Skill name
   - Brief description
   - Reason why it's recommended for this project
4. Ask the user which skill(s) they would like to execute


## Knowledge

Available audit skills in the skills directory (match keywords to recommend appropriate skills):

| Skill Name | Keywords to Match | Description |
| --- | --- | --- |
| audit-clarity-general | "clarity", "stacks", "stx", "clarity contract", "tx-sender", "contract-caller", "as-contract", "SIP-010", "SIP-009", "post-conditions", "@stacks/transactions", "@stacks/connect", "makeContractCall", "PostConditionMode", "standardPrincipalCV" | Clarity smart contract security audit |
| audit-psbt-security | "PSBT", "partially signed bitcoin transaction", "BIP-174", "BIP-370", "bitcoin signing", "sighash", "MuSig2", "Taproot signing", "multisig bitcoin", "bitcoin wallet audit", "bitcoinjs-lib", "@scure/btc-signer", "tiny-secp256k1", "ecpair", "Psbt.fromBase64", "psbt.signInput", "psbt.finalizeAllInputs" | PSBT construction, signing, and finalization security audit |
| audit-btc-marketplace-general | "Ordinals marketplace", "BRC-20 trading", "Runes marketplace", "inscription trading", "Bitcoin NFT marketplace", "ordinal listing", "inscription snipping", "Bitcoin marketplace audit", "bitcoinjs-lib", "ord indexer", "inscription UTXO" | Bitcoin Ordinals/BRC-20/Runes marketplace security audit |
| audit-btc-staking-general | "BTC staking", "Babylon staking", "Bitcoin staking protocol", "covenant", "pre-signed transaction", "EOTS", "extractable one-time signature", "finality gadget", "BTC slashing", "Bitcoin unbonding", "timelock staking", "@babylonlabs-io/btc-staking-ts" | Babylon-style BTC staking protocol security audit |
| audit-ln-dapp-general | "Lightning Network dApp", "LN swap", "submarine swap", "reverse swap", "Boltz", "Loop", "LSP", "HTLC", "preimage", "payment hash", "CLTV expiry", "channel force-close", "watchtower", "LN bridge", "PTLC", "adaptor signature", "Taproot channel", "bolt11", "ln-service", "lnrpc", "@boltz/boltz-core", "lnurl-pay" | Lightning Network dApp security audit |

**Matching Strategy:**
- Scan user input for keywords (case-insensitive)
- A project may match multiple skills - recommend all relevant ones
- Prioritize more specific skills over general ones when both match
- If no specific match, suggest general auditing approaches

## Example Usage

**Example 1:**
- Input: `"Please audit my Clarity staking contract on Stacks"`
- Agent response:
  ```
  Based on your project description, I recommend the following audit skills:

  1. audit-clarity-general
     - Clarity smart contract security audit
     - Recommended because: Your project is a Clarity contract on Stacks

  Which skill(s) would you like me to execute? You can choose one or multiple.
  ```

**Example 2:**
- Input: `"Audit my Bitcoin ordinals marketplace with PSBT signing"`
- Agent response:
  ```
  Based on your project description, I recommend the following audit skills:

  1. audit-btc-marketplace-general
     - Bitcoin Ordinals/BRC-20/Runes marketplace security audit
     - Recommended because: Your project is a Bitcoin ordinals marketplace

  2. audit-psbt-security
     - PSBT construction, signing, and finalization security audit
     - Recommended because: Your project involves PSBT signing flows

  Which skill(s) would you like me to execute?
  ```

**Example 3:**
- Input: `"Audit my submarine swap service built with Boltz"`
- Agent response:
  ```
  Based on your project description, I recommend the following audit skills:

  1. audit-ln-dapp-general
     - Lightning Network dApp security audit
     - Recommended because: Your project involves submarine swaps and Boltz integration

  Which skill(s) would you like me to execute?
  ```

---

## Output Format for Audit Findings

Once the user selects and executes an audit skill, organize the findings from the checklist into `findings.md` and save it in the project root directory. If this file already exists, append the new findings to the end.

### Rules

- Keep descriptions concise whenever possible
- First determine whether the described issue actually exists
- Output must follow directly copyable Markdown format
- Beyond formatting requirements, avoid bullet points whenever possible; clear narrative descriptions are preferred
- Functions or related variables must be enclosed in Markdown backticks, e.g., `transfer()`

### Output Structure

The output consists of five sections:

1. Title
2. File Path and Unfollowed Checkpoint
3. Description
4. Scenario
5. Recommendation

### Formatting Guidelines

**Title format:**
`{Some Issue Or Flaw} Leads To {Some Outcome}`

Capitalize every word except prepositions.

**Code location tag:**
Place above the description in the format `filename-line-range`, e.g., `AToken.sol-L11~L28`

**Description format:**
- Describe the function's purpose
- Identify the issue
- Outline potential impacts

**Scenario format:**
Provide examples using fictional users. Use bullet steps numbered sequentially:
1. Alice xxx
2. Then Bob xxx
3. ...and so on

**Fix suggestions:**
Use your discretion to provide actionable recommendations.
</content>
</invoke>