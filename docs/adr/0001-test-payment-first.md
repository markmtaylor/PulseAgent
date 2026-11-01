# ADR 0001: prove settlement before expanding the platform

Date: 2026-11-01. Status: accepted architectural baseline for implementation; acceptance still requires tests.

Use the upstream x402 v2 exact EVM implementation with explicit chain/asset configuration, an isolated signer, durable intent state and independent finalized-settlement verification. Rehearse on a disposable local EVM, then use PulseChain v4. Use a valueless EIP-3009 test token fixture compiled for Shanghai.

Reasons: official RPC responds; canonical Permit2/proxy addresses contain code; stablecoin authorization/backing, ERC-8004 registry and a usable 4337 stack are not verified. Requiring all of those for the first demonstration creates unrelated blockers. Copying native payments into an x402-shaped envelope would not prove standard interoperability.

Consequences: M1 demonstrates two deterministic agent services and real test-token settlement. It does not prove production custody, stablecoin redeemability, malicious-seller fairness or public-chain availability guarantees. Identity, 4337 and escrow are explicit follow-up gates. Mainnet signing stays disabled.

Same-day revision: runtime comparison confirmed the canonical exact Permit2 proxy matches a Cancun-compiled Ethereum reference, and read-only calls to its getter and settlement path on both PulseChain networks fail with invalid opcode MCOPY. The initial Permit2 selection is therefore superseded by standard EIP-3009 with a test fixture. No public deployment is authorized by this decision. Revisit after public-test acceptance or new verified network capabilities.
