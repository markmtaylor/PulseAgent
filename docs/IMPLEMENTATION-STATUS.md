# Implementation status

Implementation measurements by Claude Code; independent review update by
ChatGPT on 2026-11-01. Source and lockfile were independently checked in a
separate clean installation on this machine.

## What is claimed

**Milestone 1a is a working preview; acceptance is incomplete.** Two agents complete a real
payment on a disposable local EVM using the upstream x402 v2 exact scheme with
EIP-3009, and the buyer receives the result only after settlement has been
independently verified by both the seller and the buyer. The remaining blocker
is review item 29: after a lost paid response, recovery succeeds without an
extra payment but the complete audit is rejected. The passing happy path and
test suite do not cover that missing assertion.

**Milestone 1 is not complete.** Nothing has been paid on a public chain, and
this build has no code path that could: chain 943's profile declares operator
approval required and not implemented, so every signing and broadcast entry point
refuses with a specific error rather than falling back to local mode, and chain
369 is read-only with no configuration that changes it. M1b remains open.

The review ledger in `docs/REVIEW.md` is the acceptance authority. ChatGPT's
clean-install validation passed build, strict typecheck, 199 tests in 15 files,
the 22-check demo and its audit CLI. The independent recovery-audit reproduction
failed twice and keeps acceptance open.

## Measured results

Commands run from a clean build, in this order:

| Command | Result |
| --- | --- |
| `npm ci` | 0 vulnerabilities (`npm audit --omit=dev`, and with dev dependencies) |
| `npm run build` | pass, all nine workspace packages |
| `npm run typecheck` | pass, exit 0 (`tsc --build` across every package and the test sources) |
| `npx vitest run` | **199 passed, 0 failed**, 15 files, 89s, exit 0 |
| `npm run demo:local` | **22/22 checks passed**, exit 0 |
| `npm run verify:pulse` | pass; read-only, both public profiles reported their expected chain id |
| `npm run demo:testnet:plan` | exit 3 (`status: not_ready`, 6 operator values unresolved) |
| `npm run demo:testnet:execute` | exit 3, refused; does not fall back to local mode |
| `npm run audit:verify -- --manifest <run>` | acceptance check passed on the demo's own evidence |

TypeScript is strict throughout, with `noUncheckedIndexedAccess`,
`exactOptionalPropertyTypes`, `verbatimModuleSyntax` and `erasableSyntaxOnly`.

### What the demo proved, on chain

From the latest run:

- settlement verified as final and canonical, bound to the signed authorization
  nonce, with the nonce consumed on chain
- payer balance decreased and payee balance increased by **exactly** the quoted
  amount, 1500 atomic units of the valueless fixture token
- the payer holds **no** native balance: the facilitator sponsors gas
- replay and two concurrent duplicates returned the same result and the same
  receipt and charged nothing further
- a changed body under the same intent ids was refused rather than answered from
  cache, including when the quote's own digest was recomputed to match
- the local chain rejects MCOPY and TSTORE and accepts PUSH0, the same boundary
  both PulseChain networks report
- the complete lifecycle is present and linked across both audit logs, with no
  raw signature anywhere in either

Evidence from the latest run is at `.runtime/demo-2026-11-01T18-17-24-314Z/evidence/`:
`manifest.json`, `audit-platform.jsonl` (15 records), `audit-signer.jsonl`
(3 records). `.runtime/` is gitignored; re-run the demo to regenerate it.

## Repository

- Remote: https://github.com/markmtaylor/PulseAgent
- Commit at the base of this work: `31d7cd4` ("docs: specify PulseAgent milestone
  and verify PulseChain capabilities")
- Commit identity configured: `30351574+markmtaylor@users.noreply.github.com`
- This checkpoint is being published as an incomplete implementation preview.
  Check Git history and GitHub Actions for its commit and remote CI outcome;
  local validation does not imply remote CI has run.

## Running processes

**No payment services remain running.** The demo and the
integration tests start their own disposable chain, signer, facilitator and
seller, and terminate all of them in `finally` handlers; `pgrep` finds no
PulseAgent process. There is no payment daemon or continuous product service.
Claude Code reached its usage limit. Its desktop reports auto-continue enabled
for 2026-11-01 at 14:31 America/Vancouver, with the precise item-29 fix queued.
That application setting does not establish that implementation has resumed.

## Decisions forced by evidence

Three findings changed the design rather than being worked around:

1. **Permit2 is not viable on the target chains.** The canonical x402 exact
   Permit2 proxy's runtime code contains MCOPY, and both 943 and 369 reject it.
   The path is EIP-3009, as recorded in ADR 0001. No substitute proxy was etched
   at the canonical address, because that would imply a network parity that does
   not exist.
2. **The upstream `MockERC3009Token` is unusable as the fixture.** It verifies no
   signature and has no `transferWithAuthorization`, `authorizationState` or
   nonce tracking. Against it, the signer, replay and forgery tests would all
   pass for the wrong reason. `contracts/TestTokenEIP3009.sol` follows EIP-3009
   and Circle's reference implementation on OpenZeppelin bases; its three
   typehashes are asserted byte-identical to Circle's published constants.
3. **OpenZeppelin must be pinned to 5.0.2.** From 5.2 onwards `Strings` imports
   `Bytes`, whose hand-written `mcopy` makes the whole `EIP712` import graph
   Cancun-only; solc refuses to compile it for Shanghai. 5.0.2's graph compiles
   clean, so the audited upstream EIP-712 implementation is reused rather than
   replaced.

A fourth, smaller one: the local chain allows blocks to share a timestamp.
Forcing each auto-mined block strictly later than the last makes the chain's
clock run ahead of real time by a second per transaction, which expires
short-lived authorizations for reasons a public chain would not produce.

## Review findings fixed

Findings through item 28 received code fixes and regression coverage as listed
below. Independent review found a remaining audit issue, item 29; the recovery
audit is therefore not fully fixed:

| Item | What was wrong | Where it is now tested |
| --- | --- | --- |
| 1 | RPC origin comparison dropped the port | `tests/unit/chain-profiles.test.ts` |
| 2 | A caller-supplied approval string gated public broadcast | same; the gate is now a closed, unimplemented verifier |
| 5, 6, 7 | File-based store could not make check-and-reserve atomic; path collisions; empty claims | `tests/unit/store.test.ts`, now on `node:sqlite` transactions |
| 8 | Concurrent audit appends reused sequence and parent hash | `tests/unit/store.test.ts` |
| 9 | Embedded signatures survived redaction; truncation is not redaction | `tests/unit/redaction.test.ts` |
| 10 | Verifier accepted invalid lifecycle ordering | `tests/unit/audit-verify.test.ts` |
| 11 | Reservation replay ignored changed principal, asset and amount | `tests/unit/store.test.ts` |
| 12 | One intent yielded three spendable signatures | `tests/integration/signer-http.test.ts` |
| 13 | Verifier nonce optional; receipt hash uncompared | `tests/unit/settlement-verifier.test.ts` |
| 14 | Vulnerable transitive `tmp` | `overrides` pins 0.2.7; audit clean |
| 16 | Exact retry refused when the budget was exactly full | `tests/integration/signer-http.test.ts` |
| 17 | Digest fields were re-hashed, breaking linkage | `tests/unit/redaction.test.ts` |
| 18, 19 | Unconstrained broadcast: no caps, no dedupe, no payee allowlist | `tests/unit/broadcast-boundary.test.ts` |
| 20, 21 | Buyer compared the quote to itself; 202 unreachable; ambiguity terminal | `tests/integration/local-stack.test.ts` |
| 22 | Seller replay behind the payment layer; in-memory settlements; expiry blocked recovery | same |
| 23 | Evidence hashed compiler placeholders; concurrency check passed on all failures | `tests/integration/fixture-token.test.ts`, demo |
| 24 | Three MCP tools echoed upstream error text | `tests/integration/mcp-boundary.test.ts`, all six tools |
| 25 | A losing duplicate left a permanent sender-nonce gap | `tests/unit/broadcast-boundary.test.ts` |
| 26 | Recovery returned a corrupt result as DELIVERED | `tests/integration/local-stack.test.ts` |
| 27 | Linkage accepted two unrelated payments as one | `tests/unit/audit-verify.test.ts` |
| 28 | CLI argument parsing; plan incompleteness; raw fatal messages | fixed; CLI exit codes asserted in CI |

The recovery-audit work adds honest alternative events: a payment
whose response was lost has no observed submission and no verified delivery, so
the linkage check accepts `payment.unresolved`/`payment.pending` and
`result.recovered` as the honest alternatives, and `result.recovered` carries the
full correlation payload. No unobserved submission is written to satisfy a
checklist. However, the seller's `result.redelivered` event still triggers
`record_after_terminal_state`; item 29 documents the failing execution.

## Support table

| Capability | Status |
| --- | --- |
| x402 v2 exact scheme, EIP-3009, local chain 31337 | **working**, tested end to end |
| Policy engine, isolated signer, durable reservations | **working**, tested |
| Self-hosted facilitator with a constrained broadcast boundary | **working**, tested |
| Independent settlement verification, buyer and seller | **working**, tested |
| Hash-chained audit with linked cross-log lifecycle | Happy path passes; lost-response recovery audit fails (item 29) |
| MCP server over stdio, official SDK | **working locally**, tested through a real spawned stdio server |
| PulseChain 943 read-only probe | **working** |
| PulseChain 943 payment | **not implemented**; refuses explicitly |
| PulseChain 369 | **read-only**, no write path exists |
| x402 Permit2 asset transfer method | **not viable** on these chains (MCOPY) |
| Hosted facilitator | **not used**, none verified for these chains |
| Stablecoin or any asset with value | **none approved** |
| ERC-8004 identity | **not implemented**, gated |
| ERC-4337 smart accounts, bundler | **not implemented**, gated |
| Escrow, disputes, seller honesty | **not implemented**, separate milestone |
| Contract-wallet payers (ERC-1271, ERC-6492) | **untested**, out of scope for the fixture |
| Multi-host or replicated state | **not implemented**, single host |
| Performance | **not benchmarked**; no claim |

## Executed regressions

Each of these injects the real failure rather than approximating it, and each is
a repository test:

| Case | Test |
| --- | --- |
| Paid response lost after the seller settled, with `/receipt` down, then restored | `tests/integration/local-stack.test.ts` |
| Seller reports 202: the known transaction hash is saved before finality | same |
| 5xx after a possible submission stays reconcilable, never DENIED | same |
| Seller and buyer restart while the chain and signer keep running | same |
| Facilitator restart: durable claims and nonce counter carry over | same |
| Concurrent first payments, then a distinct payment that mines | same |
| A losing duplicate leaves no sender-nonce gap; signing and send failures reuse the nonce | `tests/unit/broadcast-boundary.test.ts` |
| MCP over stdio as a spawned process against the live stack | `tests/integration/mcp-stdio.test.ts` |
| All six MCP tools contain an embedded signature, bearer token and secret sentinel | `tests/integration/mcp-boundary.test.ts` |
| CLI exit codes, manifest acceptance, tampered log, unsupported manifest claim | `tests/integration/cli.test.ts` |
| On-chain forgery, replay, expiry, cancellation, wrong chain, wrong domain, wrong payer | `tests/integration/fixture-token.test.ts` |

## Open acceptance cases

1. **M1b, in full.** No verified operator approval record, no approved test asset
   on 943, no funded gas sponsor, and finalized-settlement behavior unproven
   against that chain's finality lag (660 seconds in the sampled evidence).
   `docs/M1B-PREPARATION.md` holds the plan.
2. **Recovery audit, item 29.** Allow only valid, immutably bound redelivery
   observations without reopening a terminal lifecycle. Add complete linked
   audit verification to the real lost-response regression and rerun independent
   acceptance. Clean-install happy-path validation has already passed.
3. **A multi-instance facilitator.** The durable store gives real transactions on
   one host. Two facilitator replicas sharing a database are untested, and the
   upstream pending-settlement store would need a shared implementation.

## Blockers

- **Implementation availability**: Claude Code has reached its usage limit;
  item 29 is queued in that session. ChatGPT continues review and repository work.
- **Public execution**: the operator approval verifier and concrete unsigned
  transaction preparation are not implemented. Safe implementation, read-only
  preparation and internally generated test wallets are authorized; public
  spending and deployment require the user's approval of the finished plan.
  No test asset is approved and no public gas sponsor is funded.
  `docs/M1B-PREPARATION.md` specifies the preparation work.
- **Independent audit anchoring**: hash chaining plus an external terminal hash is
  what exists. Write-once retention and independent anchoring are later controls.
- **Custody**: process separation under one OS user. A separate OS identity or
  container, and an external signer, KMS or HSM, are required before this handles
  anything of value.

## Continuous integration

`.github/workflows/ci.yml` runs on pull requests and pushes to `main`:
locked install, dependency audit, build, typecheck, the full test suite, the local
demo, and `audit:verify` against the manifest the demo wrote. It also asserts
that the public-test checklist reports itself incomplete and that public
execution refuses. Permissions are read-only, actions are pinned to commit SHAs
rather than tags, and there is no wallet secret or RPC credential in the job.
Uploaded artifacts are audit logs and manifests only, never runtime state.

Remote CI status must be checked on the implementation commit. Passing CI does
not close item 29 until its missing recovery-audit assertion is added and passes.

## Resuming

```bash
npm ci && npm run build && npx vitest run && npm run demo:local
```

Then verify the run's evidence:

```bash
npm run audit:verify -- --manifest "$(find .runtime -name manifest.json | sort | tail -1)"
```

Nothing needs to be configured first, and nothing needs to be cleaned up
afterwards beyond deleting `.runtime/`. Resume with review item 29, then the
controlled local upstream benchmark and M1b preparation. No public transaction
may execute without the user's explicit approval of a concrete plan.
