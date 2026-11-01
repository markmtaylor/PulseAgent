# PulseAgent OS

An agent payment platform built on the upstream [x402](https://github.com/x402-foundation/x402)
v2 protocol: one agent buys a service from another, pays for it on chain, and the
buyer gets the result only after the settlement has been independently verified.

**What exists today is a milestone 1a preview: a local rehearsal.** A disposable local EVM,
a valueless test token, and a complete payment between two agents that really
settles and is really verified. That is a working vertical slice and it is not a
claim about PulseChain, about production custody, or about money. What is not
done, and why, is listed in [implementation status](docs/IMPLEMENTATION-STATUS.md).
Independent clean-install verification passes 199 tests and all 22 demo checks.
Full local acceptance remains open: a lost-response recovery succeeds without a
second payment, but its audit is rejected by the verifier. See item 29 in the
[review ledger](docs/REVIEW.md). Public PulseChain settlement has not run.

## What it does

Buyer agent A wants a SHA-256 digest of a bounded input. Seller agent B sells
exactly that. The service is deterministic on purpose: it means the buyer can
recompute the answer and check that it got what it paid for, which keeps a model,
its credentials and its nondeterminism out of the evidence entirely.

```
quote  ->  402 Payment Required  ->  policy  ->  isolated signer  ->  facilitator
                                                                          |
                                      independent settlement verification |
                                                                          v
                        result released  <-  seller  <-  on-chain settlement
```

1. The buyer asks for a quote and derives the request digest itself, so a seller
   cannot price one body and be paid for another.
2. The seller answers HTTP 402 with the upstream v2 payment-required structure:
   an exact atomic amount, an asset, a chain and a payee. No dollar strings.
3. The buyer's policy engine checks the quote against operator configuration:
   origin, resource, chain, asset, payee, per-payment cap, total budget, expiry,
   request digest.
4. A separate signer process re-checks all of that against its own copy of the
   policy, rebuilds the EIP-712 message from scratch, reserves budget and gas
   atomically, binds the intent to exactly one authorization, and signs. Its key
   is generated inside it and never leaves it.
5. A self-hosted facilitator verifies the authorization and submits settlement
   once, through a broadcast boundary that constrains the call, caps the fees and
   makes a lost response recoverable rather than ambiguous.
6. The seller re-reads the chain itself: the exact transfer, the exact
   authorization nonce, a canonical block, the chain's finality rule. Only then
   does the result exist.
7. The buyer verifies the settlement again, on its own, and recomputes the
   digest before accepting the answer.

Every decision, reservation, signature, submission, receipt and delivery is
recorded in a hash-chained audit trail, with signatures reduced to digests.

## Requirements

- Node.js 24 or newer. The durable store uses `node:sqlite`, and the local chain
  uses a native EVM build; neither is optional.
- No wallet, no funded account, no API key, no paid service. There is nothing to
  configure before the demo runs.

## Running it

```bash
npm ci
```

```bash
npm run demo:local
```

That starts its own disposable chain, compiles and deploys the test fixture,
starts the signer, facilitator and seller as separate processes, performs a real
payment, runs the replay, concurrency and negative cases, writes evidence under
`.runtime/`, and stops every process in a `finally` handler. It exits nonzero if
any check fails.

```bash
npm test
```

Unit and integration tests, including the on-chain fixture cases and the full
two-agent stack.

```bash
npm run audit:verify -- --manifest .runtime/demo-<timestamp>/evidence/manifest.json
```

Re-verifies a run's evidence: hash chains, lifecycle ordering, the manifest's own
claims against the logs, and the payment's complete linked lifecycle.

```bash
npm run verify:pulse
```

A read-only capability probe against PulseChain 943 and 369. It writes dated
machine-readable evidence and signs nothing.

```bash
npm run demo:testnet:plan
```

A preparation checklist for the public-test execution. It is not an
approval-ready plan: the values only an operator can supply are left visibly
unresolved, it reports `status: not_ready`, and it exits nonzero while anything
is missing.

```bash
npm run demo:testnet:execute
```

Fails, on purpose. Public execution is not implemented, and this command exists
so that asking for it says so instead of quietly running against the local chain.

## Layout

| Path | What it is |
| --- | --- |
| `packages/core` | Chain profiles, policy engine, durable state, audit, settlement verification |
| `packages/sdk` | Buyer client: quote, pay under policy, verify, recover, read audit |
| `packages/mcp` | MCP stdio server exposing exactly those bounded operations |
| `packages/cli` | Operator commands: capability probe, unsigned plan, audit verification |
| `apps/signer` | Holds the buyer's key in its process and enforces its own policy |
| `apps/facilitator` | Self-hosted x402 facilitator with a constrained broadcast boundary |
| `apps/seller` | Seller agent: quote, 402, verify settlement, release result once |
| `apps/localchain` | **Local only.** Disposable in-process EVM and the valueless fixture |
| `examples/two-agents` | The demo and the harness the integration tests share |
| `contracts` | `TestTokenEIP3009.sol`, a valueless EIP-3009 test fixture |

## What this does not do

Stated plainly, because a payment system that overstates itself is worse than one
that does less:

- **It has not paid anything on a public chain.** Chain 943 has no broadcast path
  in this build; every signing and broadcast entry point refuses with a specific
  error rather than falling back to local mode. Chain 369 is read-only and no
  configuration changes that.
- **The test token is worthless.** It says so in its own bytecode. It is not a
  stablecoin, it is not backed, it is not redeemable, and its faucet is
  unrestricted.
- **Process separation is not custody.** The signer is a separate process and its
  key never leaves it, which prevents accidents. Under one OS user it does not
  resist a compromised host. Production custody needs a separate identity or
  container at minimum, and an external signer, KMS or HSM for anything real.
- **The audit trail is not tamper-proof.** Hash chaining detects an edited or
  removed interior record. It does not detect a log rebuilt wholesale, and it
  cannot detect a removed tail unless the terminal hash is held elsewhere.
- **It does not protect against a dishonest seller.** It proves one result per
  payment. Escrow, disputes and service quality are a separate milestone with a
  threat model this project has not written yet.
- **ERC-8004 identity, ERC-4337 smart accounts and hosted facilitators are not
  supported.** They are not integrated, not tested, and not claimed.
- **Contract-wallet payers are out of scope.** The fixture verifies ECDSA only;
  the facilitator's ERC-1271 and ERC-6492 paths are untested here.
- **No performance claim.** Nothing has been benchmarked.

## Documents

- [`docs/MILESTONE-1.md`](docs/MILESTONE-1.md) — the acceptance criteria
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — boundaries and trust model
- [`docs/RESEARCH.md`](docs/RESEARCH.md) — upstream and live-chain evidence
- [`docs/BENCHMARK-SPEC.md`](docs/BENCHMARK-SPEC.md) — reused software and the comparative benchmark plan; benchmarks have not run
- [`docs/IMPLEMENTATION-STATUS.md`](docs/IMPLEMENTATION-STATUS.md) — what is built, measured, and blocked
- [`docs/RUNBOOK.md`](docs/RUNBOOK.md) — operating and recovery procedures
- [`SECURITY.md`](SECURITY.md) — reporting, and the trust boundaries as implemented
- [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) — the security requirements this was built against
- [`docs/M1B-PREPARATION.md`](docs/M1B-PREPARATION.md) — the public-test gate
- [`docs/REVIEW.md`](docs/REVIEW.md) — the review ledger

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
