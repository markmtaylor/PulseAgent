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

At the sample, testnet's latest block was 64 blocks / 660 block-timestamp seconds ahead of finalized; mainnet's gap was 86 / 910. These are one observation, not an SLA. Public-test delivery may need minutes of asynchronous finality reconciliation; an HTTP receipt timeout must not trigger a fresh payment. Authorization expiry limits inclusion, not later confirmation of a transfer that was already included validly.

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

## Adjacent agent-wallet implementations

[Coinbase AgentKit](https://github.com/coinbase/agentkit) was also reviewed as an existing integration framework. It provides wallet/action-provider abstractions and MCP/framework integrations under Apache-2.0. Its current risk section explicitly leaves human approval, spend ceilings and destination restrictions to application developers. It is a potential future integration target, not a substitute for the signer-side policy boundary required here. No AgentKit performance benchmark or PulseChain execution has been performed.

[CDP's current wallet documentation](https://docs.cdp.coinbase.com/wallets/using-wallets/create-and-manage-wallets) distinguishes broadly EVM-capable EOAs from smart accounts with a narrower network list. This is documentation evidence, not verification that its hosted service, policies, sponsorship or smart accounts work on PulseChain. No CDP account or paid service was provisioned.

[Safe's network documentation](https://docs.safe.global/advanced/smart-account-supported-networks) separately lists smart-account versions, modules and services. The fetched page is paginated; absence from its first page is not evidence of no PulseChain deployment. Safe remains a candidate for the later ERC-4337 assessment, pending exact chain/address/module/bundler behavior checks.

AgentKit's main revision resolved through the GitHub API to `f2f3e8c11a91d56a17979a229a172ba6e61a85c2` (commit date 2026-10-14) at this observation. This is a research reference, not an installed dependency.

The immediate controlled performance baseline remains the upstream x402 flow, which is the component directly comparable to this payment slice. Broader agent frameworks solve different parts of the stack; do not present a local payment timing as a head-to-head benchmark of whole products. See BENCHMARK-SPEC.md.

## x402 protocol details

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
5. GitHub identity and destination are now verified: [markmtaylor/PulseAgent](https://github.com/markmtaylor/PulseAgent), with GitHub no-reply commit identity configured. Remote CI is not yet implemented or running.
6. Stablecoin, ERC-8004 registry, ERC-4337 bundler/account factory and escrow are future gates, not claimed support.

Read-only faucet follow-up: the official faucet's observed frontend requests `/api/info` and submits claims to `/api/claim`. The info endpoint returned a nonzero public faucet account and payout `10000000000000000000`; an independent chain-943 balance read found that account funded. Evidence: `evidence/pulse-testnet-faucet-info.json`. No claim was submitted and successful wallet funding is still unverified. A funded faucet does not guarantee a claim succeeds or remove the human approval requirement for public spending.

## Implementation dependency checks

OpenZeppelin 5.6.1 introduced a compatibility problem in the exercised EIP712/SignatureChecker dependency graph: hand-written MCOPY cannot compile for Shanghai. A separate compile probe using the official npm package 5.0.2 successfully compiled ERC20 + EIP712 + ECDSA with solc 0.8.38 and evmVersion `shanghai` (14 imports, zero compiler errors). Pin a compatible upstream release and test the complete fixture rather than replacing the upstream domain implementation. This probe is not an audit of every component in that package.

The initial npm dependency audit reported `tmp` 0.2.6 via solc. [GHSA-7c78-jf6q-g5cm](https://github.com/advisories/GHSA-7c78-jf6q-g5cm) identifies 0.2.7 as patched. Track the final lockfile resolution and rerun compilation and dependency audit; the advisory alone does not establish exploitability in this project's compiler use.

Official GitHub API release/tag checks on 2026-11-01 resolved [actions/checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1) to commit `3d3c42e5aac5ba805825da76410c181273ba90b1`, and [actions/setup-node v7.1.0](https://github.com/actions/setup-node/releases/tag/v7.1.0) to `949feb2413d6458794dcd2491c4babbbce0c15c1`. These are available immutable pins for the upcoming CI implementation; no successful workflow run is claimed yet.
