# Compatibility and upstream research

Observed 2026-11-01. Claims below distinguish live read results, documentation, and unverified behavior. Raw RPC requests and responses are retained in evidence/*.json. This is not a security audit or endorsement of any asset.

## Live PulseChain observations

| Capability | Testnet v4 | Mainnet | Meaning |
| --- | --- | --- | --- |
| Official RPC | https://rpc.v4.testnet.pulsechain.com | https://rpc.pulsechain.com | Both responded over verified TLS |
| eth_chainId | 0x3af / 943 | 0x171 / 369 | Matches official website configuration |
| web3_clientVersion | erigon/2.4.1/linux-amd64/go1.20.12 | same | Self-reported client string |
| eth_syncing | false | false | Node-reported status only |
| latest and finalized block tags | returned blocks | returned blocks | Provides a candidate finality check; not independent consensus proof |
| baseFeePerGas / gasPrice | returned | returned | EIP-1559-style block field; no signed transaction tested |
| Canonical Permit2 | 9,152 bytes | 9,152 bytes | Runtime matches verified Ethereum reference; behavior still gated |
| Canonical x402 exact Permit2 proxy | 2,913 bytes | 2,913 bytes | Runtime matches Ethereum reference but tested getter/settlement calls fail with MCOPY |
| ERC-8004 identity addresses (both upstream main/test variants) | empty | empty | These exact addresses at the observed finalized blocks only |
| EntryPoint v0.8 canonical address | empty | 21,738 bytes | Mainnet presence does not establish authentic 4337 deployment or bundler availability |
| eth_supportedEntryPoints on regular RPC | method unavailable | method unavailable | Normal RPC is not a verified bundler; not proof no bundler exists |
| Read-only opcode probes | PUSH0 works; MCOPY/TSTORE invalid | same | Compile/test for Shanghai-compatible instructions; latest EVM targets can break |

Testnet contract reads pinned block `0x1898f46`; mainnet `0x1aa7372`. Addresses and complete responses are in `evidence/pulse-*-contracts.json`. No writes were submitted.

`evidence/pulse-*-evm-opcodes.json` contains read-only creation-program `eth_call` probes at the same finalized blocks. Legacy RETURN and Shanghai PUSH0 succeeded; Cancun MCOPY and TSTORE returned explicit invalid-opcode errors. This is a test of those instructions, not a claim of full fork equivalence. Set the compiler EVM target explicitly to Shanghai (or older if a dependency requires), avoid transient-storage variants, and run the local chain with equivalent instruction restrictions. Dependencies that require Cancun cannot be assumed compatible.

**Critical follow-up:** Sourcify's API does not support chain 943, but both testnet runtime bytecodes exactly match its verified Ethereum reference bytecodes. The exact proxy reference is Solidity 0.8.28 targeting Cancun; its source matches the inspected upstream proxy. Disassembly found MCOPY at runtime offset 2032 (before metadata at offset 2860). On BOTH PulseChain endpoints, `PERMIT2()` returned the expected address, while `WITNESS_TYPE_STRING()` and an ABI-encoded `settle` simulation (intentionally invalid signature, no funds) failed with `invalid opcode: MCOPY`. Evidence: `contract-runtime-comparison.json`, `sourcify-testnet-*.json`, and `pulse-*-proxy-behavior.json`. This is a concrete incompatibility of these tested paths, not merely a compiler-target inference. **Do not use the canonical exact Permit2 proxy for M1.** Pivot to the standard EIP-3009 path with a reviewed test-only token fixture compiled for Shanghai. A compatible custom proxy deployment/configuration is a possible later alternative, not an implied authorization to deploy or replace upstream.

Official network/faucet configuration was read from [PulseChain](https://pulsechain.com/) and its deployed JavaScript asset (`/assets/index-GMnaCmvT.js` at observation time). The official faucet linked is https://faucet.v4.testnet.pulsechain.com/; its HTML responded with title PLS Testnet Faucet. Funding behavior and availability have not been demonstrated. [viem's PulseChain v4 definition](https://github.com/wevm/viem/blob/main/src/chains/definitions/pulsechainV4.ts) also records 943 and the same official RPC.

Python's local certificate store initially failed verification; the probes succeeded with system curl and normal TLS verification. No certificate verification was disabled. Evidence reflects successful probes.

## Reuse decisions

| Existing project | Use | Gap / constraint |
| --- | --- | --- |
| [x402 Foundation](https://github.com/x402-foundation/x402) | Upstream TypeScript protocol, exact EVM scheme, HTTP integration, facilitator adapters | Custom chain profile, token/deployment checks, local custody policy, durable idempotency/finality remain our responsibility |
| [viem](https://github.com/wevm/viem) | EVM client, chain definitions, ABI/log handling, signing implementation inside isolated process | Client config is not proof the remote chain matches |
| [official MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk) | Protocol transport, schema/tool registration | Avoid custom JSON-RPC; inspect installed stable release because main branch/API evolves |
| [OpenZeppelin ERC20](https://docs.openzeppelin.com/contracts/5.x/erc20) | Minimal valueless test token through inherited implementation | A mock token is not a stablecoin; compile to an explicitly tested EVM target |
| [Uniswap Permit2](https://developers.uniswap.org/docs/protocols/permit2/overview) | Existing signature-transfer contract/semantics | Prior token allowance, nonce/deadline, spender and recipient witness all matter |
| [ERC-8004 registry repository](https://github.com/erc-8004/erc-8004-contracts) | Later ABI and metadata adapter | PulseChain deployment not verified; do not recreate registries for M1 |
| [eth-infinitism account-abstraction](https://github.com/eth-infinitism/account-abstraction) | Later EntryPoint integration/reference tests | Verify exact version and license obligations; no bundler selected |

`evidence/upstream-revisions.json` records the exact upstream revisions inspected. Coinbase's repository now identifies itself as a development fork and directs upstream work to x402 Foundation. Do not base new work on an assumed historical x402 v1 interface.

## x402

The [exact EVM specification](https://github.com/x402-foundation/x402/blob/f3cb4bb79a708bf5669f952d09fa404370263c76/specs/schemes/exact/scheme_exact_evm.md) defines EIP-3009, Permit2 and ERC-7710 transfer methods. Prefer the upstream SDK rather than copying wire formats. Generic ERC-20 balances/transfers alone do not implement EIP-3009. Permit2 can serve tokens without native authorization, but needs allowance and the correct proxy/witness. Native PLS is not itself an ERC-20 exact-scheme asset.

The [EVM package documentation](https://github.com/x402-foundation/x402/blob/f3cb4bb79a708bf5669f952d09fa404370263c76/typescript/packages/mechanisms/evm/README.md) allows explicit CAIP-2 chain registration and asset amounts. Register only 943 or the owned local chain, not unrestricted wildcard networks. Self-host a facilitator configured for the chosen network. Hosted-facilitator PulseChain settlement has not been established.

Use atomic token pricing; no dollar-string fallback. The initially proposed Permit2 route is blocked by the live proxy behavior above. Use upstream exact EIP-3009 with a reviewed valueless test token fixture; verify its EIP-712 domain and nonce behavior. This does not establish any production stablecoin's support. Application idempotency, authenticated payer/request binding and finalized delivery remain additional requirements.

## Stablecoins

[Circle's supported native-USDC network list](https://www.circle.com/usdc) did not include PulseChain when checked. This does not decide every possible bridged asset's value; it means native issuer support cannot be assumed. A copied Ethereum token address/symbol is not evidence of backing or redemption. Bridged assets add bridge custody, mapping, upgrade and solvency dependencies.

No production stablecoin is approved. Before adding one: establish issuer/bridge provenance, exact chain/address, verified source and proxy implementation, decimals/domain, transfer and authorization behavior, pause/blacklist/upgrade controls, non-rebasing/non-fee semantics, liquidity/redemption assumptions and an end-to-end test. M1's test token must be visibly labeled as valueless.

## Agent identity, smart accounts and escrow

[ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) is Draft at observation and defines identity/reputation/validation separately from payments. Preserve versioned registration metadata and pinned ABIs; identity cannot replace service authentication or authorization.

[ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) is Final at observation. EntryPoint, account factory, supported bundler methods and concrete UserOperation behavior must all be tested per chain. Lack of a method on the normal RPC is not a network-wide absence claim. Keep disabled for M1.

No escrow implementation has been selected or built. Direct x402 settlement does not guarantee a dishonest seller delivers a correct service. Escrow needs a separate threat model, release/refund/dispute specification and contract review before implementation.

## Service discovery

The Stripe Directory skill was consulted first for external-provider discovery. Queries for PulseChain RPC/x402 and broader blockchain RPC did not produce a suitable verified provider. No paid infrastructure was selected or provisioned. Primary project documentation and direct read-only RPC evidence drive the initial design.

## Unresolved dependencies

1. Canonical exact Permit2 proxy fails on MCOPY: use the standard EIP-3009 test-fixture path, or separately design and verify a compatible proxy route.
2. Choose and verify a valueless test token; provision isolated signer public addresses without model access to keys.
3. Demonstrate test faucet funding and get a concrete human-approved public-test spending plan.
4. Implement and test signer isolation, exact x402 interoperability, durable recovery and independent settlement verification.
5. Confirm Git commit email and GitHub destination/authentication; remote CI is not yet running.
6. Stablecoin, ERC-8004 registry, ERC-4337 bundler/account factory and escrow are future gates, not claimed support.
