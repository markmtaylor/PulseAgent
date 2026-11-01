# Public testnet preparation and approval gate

Status: implementation requirements, not an executable plan or an approval request. M1a review must finish first. No public spending or deployment is authorized by this document.

## Prepare without spending

The operator should approve a concrete result. Preparation therefore cannot stop at placeholders that ask the user to supply private keys, invent a token address, or design the gas policy.

1. Start dedicated test signer and gas-sponsor processes. Generate disposable keys internally and emit public addresses only. Keep the processes alive while awaiting approval; a lost process invalidates its prepared plan. Never put keys in prompts, files, environment variables, arguments, logs, or model-facing tool results. Clearly document the ephemeral custody limit. Production restartable custody is a separate integration.
2. Verify chain 943 and the exact approved RPC origin with TLS verification. Refresh opcode, finalized-block and deployment capability evidence. Mainnet 369 remains unconditionally unable to sign or broadcast.
3. Choose a test asset using evidence. An existing asset needs verified code, domain, decimals and working EIP-3009 authorization semantics. Otherwise prepare an explicitly valueless, reviewed Shanghai fixture deployment. Its unrestricted test minting must be disclosed; never describe it as a stablecoin or production token.
4. If deploying the fixture, derive the expected contract address from the sponsor's public address and current nonce. Compile with the locked compiler/settings; bind artifact and bytecode hashes into the plan. Prepare deployment and mint calldata, then one service settlement. Recheck address/nonce assumptions before any execution.
5. Determine gas and fee ceilings from read-only estimates and current chain data, with explicit headroom and a total native-spend cap. Record the estimate evidence and its age. Failed estimates are unresolved dependencies, not permission to use unbounded gas. A faucet may supply valueless native test currency to a public address; receiving it does not authorize subsequent spending. No paid funding, swaps or bridges.
6. Build a bounded quote/service request and identify the payer, payee, sponsor, asset, atomic payment amount, request digest and policy revision. Publish only public identifiers and safe hashes.

Preparation may perform read-only RPC calls and generate isolated test keys internally. It must not sign a public spend authorization, submit a transaction or deploy a contract.

## Approval-ready output

The reviewable plan must name chain ID and RPC origin, public addresses, token address or predicted deployment address, bytecode provenance, every transaction/action, exact recipient and calldata digest, nonce ownership, token amount, per-transaction gas/fee maxima, cumulative native maximum, expiry, policy revision and an immutable plan digest. It must disclose that the assets are valueless test assets and identify every unresolved assumption.

A plan is ready only when required values and verification evidence exist. Incomplete output must say `not_ready`, enumerate all missing values, and return a distinguishable nonzero result. A checklist containing `OPERATOR_MUST_SUPPLY` is not a concrete transaction plan. The user must not be asked to approve it as one.

Approval must arrive through an operator-controlled interaction outside the bounded agent MCP surface and bind the exact plan digest, limits and expiry. A caller-provided boolean, nonempty approval ID, modified policy or text inside agent metadata is insufficient. Preparation and approval are separate operations. ChatGPT may explain the finished plan and request the user's explicit spending approval; it may not manufacture that approval.

## Execution and completion

The public write path must check the approved plan at the signer and sponsor boundaries, enforce one-use action identities, reserve token/native budgets before authorization, and persist transaction identity before broadcast. Refuse stale or changed plans. A lost response retains its nonce/budget and reconciles; it does not permit a fresh payment. If an earlier nonce has an uncertain outcome, block dependent work until it is reconciled instead of creating unfillable nonce gaps.

Keep service settlement pending until a canonical finalized block includes the exact transfer and authorization nonce. The observed public finality lag can exceed a short HTTP timeout. Persist the known hash immediately, allow recovery after quote expiry when inclusion was valid, and independently check the result on every delivery/recovery path.

M1b completes only with the evidence listed in MILESTONE-1.md: a real finalized chain-943 transaction, independently re-read receipt/block and exact transfer, complete correlated redacted audit, correct deterministic result, and a retry without a second charge. A local transaction, successful deployment, or passing unit suite cannot substitute for that evidence.
