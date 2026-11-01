import { AsyncLocalStorage } from "node:async_hooks";
import {
  encodeFunctionData,
  keccak256,
  type Hex,
  type Log,
  type PublicClient,
  type WalletClient,
} from "viem";
import { eip3009ABI } from "@x402/evm";
import { DurableStore, parseAtomic, randomId, type AuditLog, type BroadcastRecord } from "@pulseagent/core";

/**
 * The broadcast boundary.
 *
 * Upstream's facilitator scheme is handed a signer and will call `writeContract`
 * with whatever the scheme decides to submit. That is the right division of
 * labour for protocol logic and the wrong place to leave unconstrained: the
 * account behind it holds native gas, and the buyer-side signer's gas
 * reservation says nothing about this separate account. So every broadcast
 * passes these gates:
 *
 * 1. **Constrained call.** Only `transferWithAuthorization`, only on an
 *    allowlisted asset, and only with the payee and amount the payment
 *    requirements name. Any other address, function or argument shape is
 *    refused. `sendTransaction` — raw calldata — has no permitted use here and
 *    is refused outright.
 * 2. **Bounded cost.** An explicit gas limit and explicit fee caps, checked
 *    against configured maxima, with the worst-case fee reserved against a
 *    cumulative lifetime budget before the transaction is sent. Running out of
 *    budget stops broadcasting rather than quietly draining the account.
 * 3. **Durable dedupe before the fact.** One authorization may be broadcast
 *    once. The claim is taken, and the transaction's own hash and sender nonce
 *    are recorded, *before* the transaction reaches the network. A retry finds
 *    the recorded hash and reconciles against it instead of broadcasting a
 *    second transaction and paying gas twice.
 * 4. **Serialized nonces.** Transactions from this account are built one at a
 *    time, so two concurrent settlements cannot claim the same sender nonce and
 *    have one silently replace the other.
 *
 * The hash is known before broadcast because the transaction is signed locally
 * and hashed, then sent raw. That is what makes a lost response recoverable: the
 * hash on disk is the hash of the transaction that went out.
 */

/** What the current settlement is permitted to submit. */
export interface SettlementConstraint {
  readonly asset: `0x${string}`;
  readonly payTo: `0x${string}`;
  readonly amountAtomic: string;
  readonly network: string;
}

const settlementContext = new AsyncLocalStorage<SettlementConstraint>();

/** Runs `work` with the constraint every broadcast inside it must satisfy. */
export function withSettlementConstraint<T>(constraint: SettlementConstraint, work: () => Promise<T>): Promise<T> {
  return settlementContext.run(constraint, work);
}

export interface BroadcastLimits {
  /** Hard gas limit placed on each settlement transaction. */
  readonly maxGasLimit: bigint;
  readonly maxFeePerGasWei: bigint;
  readonly maxPriorityFeePerGasWei: bigint;
  /** Lifetime ceiling on worst-case fees this facilitator may commit, in wei. */
  readonly totalFeeBudgetWei: bigint;
}

export class BroadcastRefusedError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "BroadcastRefusedError";
    this.code = code;
  }
}

export interface ConstrainedSignerOptions {
  readonly publicClient: PublicClient;
  readonly walletClient: WalletClient;
  readonly address: `0x${string}`;
  readonly chainId: number;
  readonly network: string;
  /** Assets this facilitator may touch at all. */
  readonly allowedAssets: readonly `0x${string}`[];
  /**
   * Payees this facilitator may settle to.
   *
   * Operator configuration, not something a payment requirement can widen. A
   * requirements object arrives from a resource server, so without this the only
   * check on where funds go is that the payer signed for it — and a facilitator
   * tricked into settling a valid authorization to an attacker's address has
   * still spent its own gas doing it.
   */
  readonly allowedPayees: readonly `0x${string}`[];
  readonly limits: BroadcastLimits;
  readonly store: DurableStore;
  readonly audit: AuditLog;
  /** Identity the fee budget is tracked under. */
  readonly facilitatorId: string;
  readonly policyRevision: string;
}

/** Budget key for fees this facilitator account may commit. */
export const FACILITATOR_FEE_BUDGET_ASSET = "native:facilitator-fee";

/**
 * The immutable terms a broadcast slot is claimed for.
 *
 * Stored with the claim so a later attempt cannot reuse the slot for a different
 * payment. An EIP-3009 nonce is scoped to its token, so the claim key includes
 * the asset; these fields then pin the payee and amount as well.
 */
function termsOf(asset: string, payTo: string, amountAtomic: string): Record<string, string> {
  return { asset: asset.toLowerCase(), payTo: payTo.toLowerCase(), amountAtomic };
}

/** Rejects a slot whose recorded terms are not the ones now being asked for. */
function assertSameTerms(record: BroadcastRecord, expected: Record<string, string>): void {
  for (const [field, value] of Object.entries(expected)) {
    if (record.terms[field] !== value) {
      throw new BroadcastRefusedError(
        "broadcast_binding_changed",
        "this authorization was already claimed under different asset, payee or amount terms",
      );
    }
  }
}

/**
 * Builds the write side of a {@link FacilitatorEvmSigner} with the gates above.
 *
 * @param options Clients, allowlist, limits and durable state.
 * @returns `writeContract` / `sendTransaction` implementations to hand upstream.
 */
export function createConstrainedWriter(options: ConstrainedSignerOptions): {
  writeContract(args: {
    address: `0x${string}`;
    abi: readonly unknown[];
    functionName: string;
    args: readonly unknown[];
    gas?: bigint;
    dataSuffix?: `0x${string}`;
  }): Promise<`0x${string}`>;
  sendTransaction(args: { to: `0x${string}`; data: `0x${string}` }): Promise<`0x${string}`>;
  waitForTransactionReceipt(args: {
    hash: Hex;
    timeout?: number;
  }): Promise<{ status: string; logs?: readonly Log[] }>;
} {
  const { publicClient, walletClient, store, audit, limits } = options;
  const allowedAssets = new Set(options.allowedAssets.map((asset) => asset.toLowerCase()));
  const allowedPayees = new Set(options.allowedPayees.map((payee) => payee.toLowerCase()));
  if (allowedPayees.size === 0) {
    throw new Error("a facilitator must be configured with at least one allowed payee");
  }

  // Nonce allocation and signing happen one at a time for this account.
  let serialized: Promise<unknown> = Promise.resolve();
  const inOrder = <T>(work: () => Promise<T>): Promise<T> => {
    const result = serialized.then(work, work);
    serialized = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  };

  return {
    async writeContract(args) {
      const constraint = settlementContext.getStore();
      if (!constraint) {
        throw new BroadcastRefusedError(
          "no_settlement_context",
          "a broadcast was attempted outside a settlement with declared constraints",
        );
      }
      if (args.functionName !== "transferWithAuthorization") {
        throw new BroadcastRefusedError(
          "function_not_allowed",
          `this facilitator submits only transferWithAuthorization, not ${args.functionName}`,
        );
      }
      if (!allowedAssets.has(args.address.toLowerCase())) {
        throw new BroadcastRefusedError("asset_not_allowed", "target contract is not an allowlisted asset");
      }
      if (args.address.toLowerCase() !== constraint.asset.toLowerCase()) {
        throw new BroadcastRefusedError(
          "asset_mismatch",
          "target contract is not the asset this settlement is for",
        );
      }
      if (args.dataSuffix !== undefined && args.dataSuffix !== "0x") {
        throw new BroadcastRefusedError("data_suffix_not_allowed", "appended calldata is not permitted");
      }

      const call = parseTransferWithAuthorizationArgs(args.args);
      if (call.to.toLowerCase() !== constraint.payTo.toLowerCase()) {
        throw new BroadcastRefusedError("payee_mismatch", "transfer payee is not the payee this settlement names");
      }
      if (!allowedPayees.has(call.to.toLowerCase())) {
        throw new BroadcastRefusedError(
          "payee_not_allowed",
          "transfer payee is not an operator-allowlisted recipient for this facilitator",
        );
      }
      if (call.value !== BigInt(constraint.amountAtomic)) {
        throw new BroadcastRefusedError("amount_mismatch", "transfer amount is not the amount this settlement names");
      }

      // One authorization, one broadcast. The asset is part of the key because an
      // EIP-3009 nonce is scoped to its token: the same payer and nonce on two
      // different tokens are two different authorizations.
      const authorizationKey =
        `${options.network}:${args.address.toLowerCase()}:${call.from.toLowerCase()}:${call.nonce.toLowerCase()}`;
      const terms = termsOf(args.address, call.to, call.value.toString(10));

      const already = store.readBroadcast(authorizationKey);
      if (already?.txHash !== undefined) {
        assertSameTerms(already, terms);
        audit.append({
          actor: "facilitator",
          kind: "facilitator.broadcast.deduplicated",
          payload: {
            transactionHash: already.txHash,
            senderNonce: already.senderNonce,
            authorizationNonce: call.nonce,
            payer: call.from,
          },
        });
        return already.txHash as Hex;
      }

      const gas = args.gas ?? (await estimateBoundedGas());
      if (gas > limits.maxGasLimit) {
        throw new BroadcastRefusedError(
          "gas_limit_exceeded",
          `settlement needs ${gas.toString(10)} gas, above the configured limit of ${limits.maxGasLimit.toString(10)}`,
        );
      }

      const fees = await publicClient.estimateFeesPerGas();
      const maxFeePerGas = fees.maxFeePerGas ?? limits.maxFeePerGasWei;
      const maxPriorityFeePerGas = fees.maxPriorityFeePerGas ?? limits.maxPriorityFeePerGasWei;
      if (maxFeePerGas > limits.maxFeePerGasWei) {
        throw new BroadcastRefusedError(
          "fee_cap_exceeded",
          `network max fee ${maxFeePerGas.toString(10)} wei exceeds the configured cap`,
        );
      }
      if (maxPriorityFeePerGas > limits.maxPriorityFeePerGasWei) {
        throw new BroadcastRefusedError("priority_fee_cap_exceeded", "network priority fee exceeds the configured cap");
      }

      const worstCaseFeeWei = gas * maxFeePerGas;
      const reservation = store.reserveBudget({
        principalId: options.facilitatorId,
        policyRevision: options.policyRevision,
        intentId: `fac_${authorizationKey}`,
        idempotencyKey: `fac_${authorizationKey}`,
        reservationId: randomId("fee"),
        legs: [
          {
            asset: FACILITATOR_FEE_BUDGET_ASSET,
            amountAtomic: worstCaseFeeWei.toString(10),
            maxAmountPerPayment: (limits.maxGasLimit * limits.maxFeePerGasWei).toString(10),
            totalBudget: limits.totalFeeBudgetWei.toString(10),
          },
        ],
      });
      if (!reservation.ok) {
        throw new BroadcastRefusedError(
          reservation.code,
          `fee budget refused this settlement: ${reservation.reason}`,
        );
      }

      return inOrder(async () => {
        const nodePending = await publicClient.getTransactionCount({
          address: options.address,
          blockTag: "pending",
        });
        // The claim and the nonce are taken together. A duplicate that loses here
        // has allocated nothing, so it cannot leave a permanent gap in this
        // account's nonce sequence.
        const slot = store.claimBroadcastSlot({
          key: authorizationKey,
          senderKey: `${options.network}:${options.address.toLowerCase()}`,
          nodePendingNonce: nodePending,
          terms,
        });

        if (!slot.claimed) {
          assertSameTerms(slot.record, terms);
          if (slot.record.txHash !== undefined) {
            audit.append({
              actor: "facilitator",
              kind: "facilitator.broadcast.deduplicated",
              payload: {
                transactionHash: slot.record.txHash,
                senderNonce: slot.record.senderNonce,
                authorizationNonce: call.nonce,
                payer: call.from,
              },
            });
            return slot.record.txHash as Hex;
          }
          // The slot exists with no hash: a previous attempt claimed it and did
          // not finish. Rebuild the same transaction with the same nonce so the
          // hash is identical, rather than consuming a second nonce.
        }
        const senderNonce = slot.claimed ? slot.senderNonce : slot.record.senderNonce;

        const data = encodeFunctionData({
          abi: eip3009ABI,
          functionName: "transferWithAuthorization",
          args: args.args as never,
        });
        // Signed locally so its hash is known before it is sent. That hash is
        // what makes a lost or timed-out response recoverable rather than
        // ambiguous.
        const signedTransaction = await walletClient.signTransaction({
          account: walletClient.account ?? options.address,
          chain: null,
          to: args.address,
          data,
          value: 0n,
          gas,
          maxFeePerGas,
          maxPriorityFeePerGas,
          nonce: senderNonce,
          chainId: options.chainId,
          type: "eip1559",
        } as never);
        const hash = keccak256(signedTransaction);

        store.recordBroadcastHash(authorizationKey, hash);
        audit.append({
          actor: "facilitator",
          kind: "facilitator.broadcast.recorded",
          payload: {
            transactionHash: hash,
            senderNonce,
            authorizationNonce: call.nonce,
            payer: call.from,
            payTo: call.to,
            amountAtomic: call.value.toString(10),
            asset: args.address,
            gasLimit: gas.toString(10),
            maxFeePerGasWei: maxFeePerGas.toString(10),
            worstCaseFeeWei: worstCaseFeeWei.toString(10),
          },
        });

        try {
          await publicClient.sendRawTransaction({ serializedTransaction: signedTransaction });
        } catch (error) {
          // The hash and nonce are already recorded, so this is an unknown
          // outcome rather than a failure: the transaction may have reached the
          // network anyway. The claim stays, which is what stops a second
          // broadcast and a second nonce on the next attempt.
          audit.append({
            actor: "facilitator",
            kind: "facilitator.broadcast.outcome_unknown",
            payload: {
              transactionHash: hash,
              senderNonce,
              authorizationNonce: call.nonce,
              code: "send_raw_transaction_failed",
            },
          });
          throw error;
        }
        return hash;
      });

      async function estimateBoundedGas(): Promise<bigint> {
        try {
          const estimate = await publicClient.estimateContractGas({
            address: args.address,
            abi: eip3009ABI,
            functionName: "transferWithAuthorization",
            args: args.args as never,
            account: options.address,
          });
          // Headroom for block-to-block variation, still under the hard cap.
          return (estimate * 120n) / 100n;
        } catch {
          return limits.maxGasLimit;
        }
      }
    },

    async sendTransaction() {
      // Upstream uses this only for ERC-6492 smart-wallet deployment, which this
      // build does not enable. Raw calldata from a protocol library is exactly
      // what a constrained broadcast boundary exists to refuse.
      throw new BroadcastRefusedError(
        "raw_transaction_not_allowed",
        "this facilitator does not submit raw transactions",
      );
    },

    async waitForTransactionReceipt(args) {
      const receipt = await publicClient.waitForTransactionReceipt({
        hash: args.hash,
        ...(args.timeout === undefined ? {} : { timeout: args.timeout }),
      });
      return { status: receipt.status, logs: receipt.logs };
    },
  };
}

/** Validates the argument tuple upstream passes for an EIP-3009 transfer. */
function parseTransferWithAuthorizationArgs(args: readonly unknown[]): {
  from: `0x${string}`;
  to: `0x${string}`;
  value: bigint;
  nonce: `0x${string}`;
} {
  // Either the (v, r, s) form or the (signature) form; both share the first six.
  if (args.length !== 9 && args.length !== 7) {
    throw new BroadcastRefusedError("unexpected_arguments", "settlement call has an unrecognized argument shape");
  }
  const [from, to, value, validAfter, validBefore, nonce] = args;
  if (!isAddress(from) || !isAddress(to) || !isBytes32(nonce)) {
    throw new BroadcastRefusedError("unexpected_arguments", "settlement call arguments are not well formed");
  }
  if (typeof value !== "bigint" || typeof validAfter !== "bigint" || typeof validBefore !== "bigint") {
    throw new BroadcastRefusedError("unexpected_arguments", "settlement call amounts are not integers");
  }
  if (value <= 0n) {
    throw new BroadcastRefusedError("amount_not_positive", "settlement amount must be positive");
  }
  parseAtomic(value.toString(10), "settlement value");
  return { from, to, value, nonce };
}

function isAddress(value: unknown): value is `0x${string}` {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value);
}

function isBytes32(value: unknown): value is `0x${string}` {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}
