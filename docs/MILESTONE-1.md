# Milestone 1: verifiable agent payment

Owner: Claude Code (implementation), ChatGPT (architecture/review). Specification date: 2026-11-01.

## Outcome

Agent A buys one deterministic service from agent B using x402 v2 on PulseChain test infrastructure. The buyer receives the result only after independently verified settlement. A third party can reproduce the flow and inspect the complete redacted audit trail.

**M1a is a local prerequisite, not completion of M1.** Run a disposable local EVM (31337) with random runtime-generated wallets and valueless ERC-20 tokens. **M1b is the acceptance milestone:** execute the same flow on public PulseChain v4 (943), record a real transaction and finalized verification. A PulseChain fork alone does not satisfy M1b. Mainnet 369 is read-only and cannot be enabled by changing one boolean.

## Smallest useful demonstration

Use two deterministic agent services, explicitly labeled as such: buyer requests a SHA-256 digest service; seller computes the digest of a bounded input. No LLM credential is necessary for reproducibility. Actual LLM-driven agents can use the same SDK/MCP later.

1. Request a quote for a bounded input; create a random quote ID, expiry, request digest and payment intent ID.
2. Seller returns HTTP 402 with the upstream v2 PAYMENT-REQUIRED structure and an exact atomic token amount, asset address, chain and payee. No assumed dollar price.
3. Buyer's policy engine checks the normalized quote against its configured service origin, chain, asset, recipient, per-payment amount, total budget, expiry, and request digest.
4. An isolated signer validates those same constraints and the upstream EIP-712 domain/type/message before authorizing. It reserves budget durably and never exposes the key. Bound gas sponsorship separately.
5. Buyer retries through the upstream x402 flow. Self-hosted facilitator verifies the authorization and submits settlement once. Do not depend on an unverified hosted facilitator supporting 943.
6. Seller verifies the actual chain receipt/logs, exact transfer and canonical block. Local mode may use a documented confirmation rule; public test mode requires finalized block inclusion or reports a pending/blocker state. Bounded polling can resume later without paying twice.
7. Seller releases the deterministic result and payment receipt. Buyer verifies the result digest and settlement independently.
8. Replay the same request and concurrently retry it: return the same result/receipt and do not charge again. A changed body with the same ID must fail.

## Implementation scope

Use npm workspaces: packages/core (types, chain config, policy, audit/state), packages/sdk (buyer client), packages/mcp (official stdio MCP server), apps/signer (separate process), apps/facilitator (upstream x402), apps/seller, examples/two-agents, tests. Consolidate tiny packages if necessary; keep signer trust boundary real.

Compile contracts explicitly for Shanghai-compatible instructions and configure the local EVM accordingly. Live read-only probes on both PulseChain networks rejected MCOPY and TSTORE (see RESEARCH.md). Avoid modern dependencies requiring Cancun/transient storage unless separately proven compatible.

Use the upstream exact EVM EIP-3009 path with a reviewed upstream test-only token fixture compiled for Shanghai. The initial Permit2 proposal was invalidated by live behavior probes: the canonical exact proxy contains MCOPY and its tested settlement path fails on both PulseChain networks (see RESEARCH.md). Do not etch a Shanghai-recompiled proxy at the canonical address locally and present it as public-network parity. Reuse an upstream EIP-3009 fixture or a narrowly reviewed test-only adaptation with provenance; do not create new production cryptography/payment contracts. No invented stablecoin, escrow, registry, or smart account is required for M1.

Public test token decision remains gated: use an independently verified existing test token or a reviewed, explicitly approved mock deployment. Call it a test token, never a redeemable stablecoin. Public native gas is tPLS. Do not request a user private key.

## Required commands / artifacts

- `npm ci`, `npm run build`, `npm run typecheck`, `npm test`: clean checkout, no real credentials.
- `npm run demo:local`: starts its own disposable chain/processes, executes real local transactions, validates result, writes redacted evidence, stops processes in finally handlers.
- `npm run verify:pulse`: read-only capability probe with machine-readable dated evidence and clear failures.
- `npm run demo:testnet:plan`: unsigned concrete transaction plan, public addresses, assets, allowances, maximum gas and spending; no signing side effects.
- Public execution command only after human approval via an operator channel inaccessible to model tools. If not implemented yet, fail explicitly; never silently run local mode instead.
- `npm run audit:verify -- <file>`: checks sequence, hash chain, intent linkage, settlement and terminal state completeness. Explain that a locally rewritable log is not independently tamper-proof.
- GitHub Actions: locked install, build/typecheck, unit/integration tests and local demo on pull requests. Minimal permissions, no wallet secrets. Pin actions to reviewed commit SHAs. Save safe test reports; never upload credentials or signer runtime state.
- README, open-source license, security policy, runbook and implementation status with truthful support table.

## Acceptance tests (must demonstrate failures safely)

| Area | Acceptance |
| --- | --- |
| Happy path | 402 → authorization → on-chain settlement → verified digest result; exact payer decrease/payee increase for non-fee token; one payment |
| Chain isolation | Mainnet, unknown chain, spoofed RPC chain ID, cross-chain signature and local-only methods on remote RPC rejected |
| Policy | Wrong payee/token/origin, invalid address, zero/negative/fractional/overflow amount, excessive amount/gas, unknown fields and expired quote rejected before signing |
| Signer | Invalid domain/verifying contract/type/spender/witness, wrong principal, arbitrary calldata and unrecognized method rejected; no keys in tool schemas or outputs |
| Settlement | Revert, missing/wrong log, wrong amount/from/to/token, transaction on wrong chain, stale receipt, removed block or insufficient finality cannot release service |
| Replay | Concurrent duplicates and retries after restart charge once; another quote/body cannot consume an old proof; same token authorization nonce cannot pay again |
| Crash recovery | Crash after durable intent, submission, or settlement reconciles by saved nonce/hash; no blind rebroadcast with fresh authorization; ambiguous cases stay pending |
| Audit | Every decision/intent/approval/reservation/signing event (no signature secret)/submission/receipt/finality/delivery linked by IDs; edits and truncation against a known terminal hash detected |
| MCP | Official client initializes, lists tools and invokes quote/status/payment request; requests go through policy; spending approval and generic signing are absent |
| Reproducibility | A clean dependency install executes the complete local demo, cleans child processes and produces useful nonzero exits on failures |

## Gate to M1b completion

Require a finalized transaction on chain 943 with transaction/block hashes, block numbers, token address/code hash/decimals, payer/payee public addresses, amount, fees, quote/request/result digests, policy revision and operator approval record. Independently re-read receipt and canonical blocks. Audit replay and retry test must pass. Record dependency lockfile and Git commit. Publish no private keys or live payment authorizations.

A build passing locally, deployed contract, HTTP success, model narrative, or transaction hash alone is not sufficient.
