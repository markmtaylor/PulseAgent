# Upstream reuse and benchmark specification

Status: specification only. No comparative performance benchmark has been run or claimed. Correctness and recovery acceptance remain the first gate.

## Reused implementations

| Component | Upstream used | Declared package license | PulseAgent responsibility |
| --- | --- | --- | --- |
| x402 v2 exact EVM payment | x402 Foundation core/evm/fetch/express 2.29.0 | Apache-2.0 | Explicit chain/asset configuration, policy enforcement, durable request binding, recovery and independent finality checks |
| EVM clients and signing primitives | viem 2.57.14 | MIT | Isolated key-bearing processes and constrained interfaces |
| ERC-20, EIP-712 and ECDSA bases | OpenZeppelin Contracts 5.0.2 | MIT | Narrow valueless EIP-3009 fixture adaptation and compatibility tests |
| Disposable Shanghai EVM | Hardhat EDR 0.25.0 | MIT | Owned loopback lifecycle and test provisioning |
| Solidity compilation | solc 0.8.38 | MIT | Locked Shanghai target, fixture provenance and runtime verification |
| MCP protocol | Official TypeScript MCP SDK 1.32.2 | MIT | Bounded agent-facing operations through the payment SDK |
| Durable transactions | Node 24 built-in SQLite | See Node distribution notices | Application policy, reservation, nonce and audit schemas |

Exact dependency versions and integrity values live in package-lock.json. RESEARCH.md records upstream revisions and compatibility evidence. This table describes dependencies, not an assertion that an entire upstream product has been benchmarked or that all its features work on PulseChain.

Versions and declared licenses above were read from the installed lockfile on 2026-11-01. Preserve each dependency's notices when distributing it; this short table is not a complete transitive-license inventory. AgentKit and Safe are research candidates only, not installed dependencies or measured baselines.

## Controlled comparison

Compare an upstream-only x402 exact EIP-3009 buyer/seller/facilitator flow with PulseAgent's flow, using the same pinned upstream libraries, token fixture, compiler settings, chain, price, service input size, receipt rule and machine. Generate all disposable keys inside test processes and emit no secret material. Do not disable PulseAgent's controls to improve a score.

Exclude installation, compilation and service startup from per-payment latency; report those costs separately. Keep sender/recipient storage conditions equivalent, use fresh authorization nonces, and record warm-up policy. Begin with sequential transactions. Add controlled concurrent workloads only after duplicate-request and budget tests pass.

For each measured payment retain mode, run number, monotonic elapsed timings, gas used, transaction/block hashes, exact balance changes, outcome, request/result digests and package-lock/Git revision. Report sample count, median, minimum and maximum; report percentiles only with enough samples and disclose the method. Separate quote latency, authorization latency, submission/inclusion latency, verification/delivery latency and total elapsed time.

Measure extra transactions and gas on retries explicitly. A faster result obtained before required settlement verification is not comparable. Report which policy/recovery/audit controls each mode exercises; an upstream baseline without an application policy layer is not a claim about that upstream project's security.

## Limits

Chain-31337 timings measure the local development environment. They do not establish PulseChain throughput, network latency, public finality or monetary costs. Public-chain measurements require the approved M1b setup and the user's spending authorization. Publish raw redacted samples with any benchmark conclusion; do not invent results from architecture or extrapolate local timing into public-network performance claims.
