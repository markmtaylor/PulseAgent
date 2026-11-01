# Security review baseline

Status: requirements for the first implementation; controls are not presumed implemented. Date: 2026-11-01.

## Assets and trust boundaries

Protect wallet keys, payment/fee budgets, transaction nonce state, paid-service results, task integrity, and audit evidence. The buyer agent, seller response, discovery metadata, HTTP headers and model-generated tool arguments may be malicious. The local operator controls policy and approves any public spending. RPC responses are external evidence, not absolute truth. Development assumes the host OS and selected dependencies are trustworthy; that assumption is not a production custody guarantee.

## Abuse cases and required evidence

| Threat | Required control | Review evidence |
| --- | --- | --- |
| Prompt injection requests arbitrary transfer | No raw signing/calldata MCP interface; allowlist exact typed intent at signer boundary | Malicious payee/asset/domain/spender tests show zero signing side effects |
| Agent changes its budget or invents approval | Operator policy loaded outside model APIs; revision and intent-bound approval checked by signer | Caller-supplied approval flags cannot authorize |
| Parallel requests overspend | Atomic persistent reservations include all authorized/in-flight payments and gas | Concurrency test exceeds aggregate budget and rejects excess |
| RPC URL resolves to wrong chain | Pinned endpoint profile plus actual chain ID check before signing; unknown chains fail closed | Wrong-chain mock/test endpoint rejects |
| Local test funding targets a real network | Owned loopback process with explicit local profile; no public setBalance/etch/impersonation | Local bootstrap rejects a remote URL even if it reports 31337 |
| x402 authorization redirects funds | Strict scheme/domain/types/token/amount/spender/recipient witness validation | Mutated signed fields and mismatched quote fail |
| A proof buys different work | Bind quote, request digest, principal and authorization nonce durably | Reuse same proof for a new body/quote rejected |
| Retry or restart charges twice | Durable uniqueness, transaction hash/nonce persistence and reconciliation | Concurrent retries plus restart at side-effect boundaries |
| Receipt spoofing or reorg delivers unpaid work | Independent RPC reads of status, exact log fields, chain and canonical/finalized block | Altered log and canonical hash tests deny delivery |
| Network timeout releases budget too early | Keep RECONCILING reservation until settlement/revert/expiry is proven | Indeterminate broadcast cannot obtain fresh payment budget |
| Infinite ERC-20 approval enlarges exposure | Exact/bounded token allowance; separate approval cap and approved spender | Excess allowance request denied; no maxUint256 convenience approval |
| Facilitator gas drain | Auth/rate limits, simulate, bounded gas and fee caps, independent total gas budget | Invalid authorizations cannot trigger unbounded paid transactions |
| SSRF via quote/discovery metadata | Configured origins, no redirects/private-network traversal for remote resources, size/time limits | Redirect, credential-bearing URL and alternate-host rejection |
| Key leak through error, test node or log | Keys generated/held inside signer process; bounded sanitized errors and output allowlist | Secret-sentinel/redaction tests and captured child stdout review |
| Audit rewritten or truncated | Hash chain plus trusted manifest terminal hash/state; fail closed on write failure | Edit/reorder/delete/truncation detection relative to manifest |
| Dependency compromise | Pin lockfile and CI actions; no unnecessary install scripts/secret-bearing CI | Dependency audit reviewed; provenance/license notices retained |

## Limits that must remain explicit

- A separate process under the same OS user is not an HSM and does not resist a compromised developer host. Do not run this milestone with valuable keys.
- Agent identity, a valid signature, and a settled payment do not prove the seller's answer is correct. The deterministic digest demo checks its own output; general task escrow/disputes are future work.
- A single RPC's finalized response is not independent consensus validation. Production needs a defined node/provider trust model and outage/reorg monitoring.
- In-flight signed authorizations may be redeemable even after a client disconnects. Do not free their budget merely because the HTTP request timed out.
- Test tokens and copied/bridged stablecoin symbols do not establish dollar backing, redemption or liquidity.
- No mainnet signing/deployment path is accepted in M1. Any future enablement needs separate code review, concrete spending/deployment plan and human authorization.

## Public-test transaction plan

Before asking for spending approval, produce a reviewable plan containing chain 943, exact signer public addresses, selected RPC, token/proxy addresses and authenticated code hashes, calldata intent for each deployment/mint/approval/payment, atomic amounts, maximum allowance, gas-limit and fee ceilings, cumulative tPLS bound, expiry, idempotency key, and expected settlement condition. Bind approval to the digest of this plan. A changed plan requires fresh approval. Never ask for private keys in chat.
