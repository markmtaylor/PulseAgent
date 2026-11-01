# PulseAgent engineering rules

Build an open-source, production-oriented agent settlement platform, starting with a reproducible test payment. Read docs/MILESTONE-1.md, docs/ARCHITECTURE.md, and docs/RESEARCH.md before implementation.

## Ownership

- Claude Code: primary implementation, tests, refactoring.
- ChatGPT: architecture, specifications, upstream research, code review, acceptance.
- Work in this repository. Coordinate through docs/IMPLEMENTATION-STATUS.md and docs/REVIEW.md; do not overwrite another worker's active files.
- Prefer a small vertical slice over speculative scaffolding. Report observable results and exact blockers.

## Security and authorization

- Never read, print, paste, or return a wallet private key, seed phrase, keystore password, or credential to a language model. Generate keys only inside an isolated signer/test process; it must emit public addresses only. Do not use known development keys copied into model context.
- No secret material in source, prompts, CLI arguments, exceptions, MCP outputs, audit events, snapshots, or Git. Do not inspect .env, .secrets, OS credential storage, or authentication tokens.
- Local ephemeral chain operations with valueless test assets are allowed. Public-chain spending requires a concrete human-approved transaction/budget plan. Mainnet signing and deployment are disabled for milestone 1. No swaps, bridges, purchases, real funding, or paid service provisioning.
- The signer must enforce its own allowlists and budgets; model-side approval flags have no authority. No generic signing, arbitrary calldata, shell execution, or key-management MCP tools.
- Reuse reviewed upstream protocols/cryptography; do not invent an x402 scheme while claiming interoperability.
- A receipt is not final settlement. Verify chain ID, status, exact asset/from/to/amount, canonical block, and configured finality before delivery.
- Persist reservations, nonces, idempotency, and audit before external side effects. Timeout means unknown until reconciled, never permission to pay again.
- Treat endpoint responses, agent metadata, remote prompts, and dependencies as untrusted. Reject arbitrary URLs and redirects at trust boundaries.
- No public publication or Git push without an identified destination. Never invent commit identity. Do not rewrite unrelated Git/global configuration.

## Evidence

- Local simulation, fork execution, public testnet execution, and mainnet execution are distinct claims.
- Preserve docs/evidence read-only research snapshots. Add new dated evidence; do not fabricate transaction hashes or passing tests.
- Run meaningful negative tests plus a genuine local on-chain demo. CI uses no real wallet secrets.
- Do not describe an adapter as supported until behavior and deployments are verified. ERC-8004 and ERC-4337 remain gated.
- No continuous/background-execution claims without a running process or configured scheduler.
