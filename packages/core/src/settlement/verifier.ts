import { decodeEventLog, type Hex, type Log, type PublicClient } from "viem";
import type { ChainProfile } from "../chain/profiles.js";

/**
 * Independent settlement verification.
 *
 * A facilitator's receipt is a claim, not a settlement. Nothing is released on
 * the strength of an HTTP 200, a transaction hash, or a `success: true` field.
 * This module re-reads the chain itself and insists on:
 *
 * - the node being on the expected chain
 * - a receipt with execution status success
 * - the exact ERC-20 `Transfer(from, to, value)` the quote priced, emitted by
 *   the expected asset contract
 * - the EIP-3009 `AuthorizationUsed(authorizer, nonce)` for the exact
 *   authorization that was signed, so the settlement is bound to that
 *   authorization and not merely to a transfer that happens to match
 * - the receipt's block still being the canonical block at its height
 * - the profile's finality rule
 *
 * The signature's own validity window is deliberately not re-checked here. Once
 * a transfer is included, a later finalization delay does not invalidate it, and
 * re-testing `validBefore` after inclusion would reject good settlements.
 */

/** ERC-20 Transfer, the event any correct token transfer must emit. */
const TRANSFER_EVENT = {
  type: "event",
  name: "Transfer",
  inputs: [
    { name: "from", type: "address", indexed: true },
    { name: "to", type: "address", indexed: true },
    { name: "value", type: "uint256", indexed: false },
  ],
} as const;

/** EIP-3009 AuthorizationUsed, which binds a settlement to one authorization. */
const AUTHORIZATION_USED_EVENT = {
  type: "event",
  name: "AuthorizationUsed",
  inputs: [
    { name: "authorizer", type: "address", indexed: true },
    { name: "nonce", type: "bytes32", indexed: true },
  ],
} as const;

export interface SettlementExpectation {
  readonly txHash: Hex;
  readonly asset: `0x${string}`;
  readonly from: `0x${string}`;
  readonly to: `0x${string}`;
  /** Exact atomic amount. A transfer of a different amount is a mismatch, either way. */
  readonly amountAtomic: string;
  /**
   * The EIP-3009 authorization nonce that was signed. Required, not optional: a
   * matching Transfer alone only proves that *some* transfer of the right
   * amount between the right parties happened, which an unrelated transaction
   * can also satisfy. Binding to the nonce is what makes this settlement
   * provably the authorized payment, so there is no code path that skips it.
   */
  readonly authorizationNonce: Hex;
}

export interface SettlementFacts {
  readonly chainId: number;
  readonly txHash: string;
  readonly blockNumber: string;
  readonly blockHash: string;
  readonly asset: string;
  readonly from: string;
  readonly to: string;
  readonly amountAtomic: string;
  readonly gasUsed: string;
  readonly effectiveGasPriceWei: string;
  readonly confirmations: string;
  readonly finalityRule: "confirmations" | "finalized-tag";
  /** The authorization nonce this settlement provably consumed. */
  readonly authorizationNonce: string;
  readonly verifiedAtUnix: number;
}

export type SettlementVerdict =
  /** Verified and final under the profile's rule. Safe to release a result. */
  | { readonly status: "final"; readonly facts: SettlementFacts }
  /**
   * Verified as included and correct, but not yet final. Not safe to release on
   * a public chain; the caller should resume polling, which never costs a second
   * payment because the intent and its nonce are already durable.
   */
  | { readonly status: "pending-finality"; readonly facts: SettlementFacts; readonly reason: string }
  /** No receipt yet. Outcome unknown, so the payment stays in flight. */
  | { readonly status: "pending-inclusion"; readonly reason: string }
  /** The transaction executed and failed. No payment occurred. */
  | { readonly status: "reverted"; readonly reason: string }
  /** The receipt's block is no longer canonical, so the receipt is stale. */
  | { readonly status: "not-canonical"; readonly reason: string }
  /** Included, but it is not the payment that was authorized. */
  | { readonly status: "mismatch"; readonly reason: string };

/** The chain reads this verifier needs. Narrow, so tests can supply a fake. */
export interface SettlementReader {
  getChainId(): Promise<number>;
  getReceipt(hash: Hex): Promise<
    | {
        /** The hash the node reports for this receipt, compared against the request. */
        transactionHash: Hex;
        status: "success" | "reverted";
        blockNumber: bigint;
        blockHash: Hex;
        gasUsed: bigint;
        effectiveGasPrice: bigint;
        logs: readonly Log[];
      }
    | undefined
  >;
  getBlockHashAtNumber(blockNumber: bigint): Promise<Hex | undefined>;
  getLatestBlockNumber(): Promise<bigint>;
  /** The node's `finalized` block number, or undefined when it serves no such tag. */
  getFinalizedBlockNumber(): Promise<bigint | undefined>;
}

/** Adapts a viem public client to {@link SettlementReader}. */
export function createViemSettlementReader(client: PublicClient): SettlementReader {
  return {
    async getChainId() {
      return client.getChainId();
    },
    async getReceipt(hash) {
      try {
        const receipt = await client.getTransactionReceipt({ hash });
        return {
          transactionHash: receipt.transactionHash,
          status: receipt.status,
          blockNumber: receipt.blockNumber,
          blockHash: receipt.blockHash,
          gasUsed: receipt.gasUsed,
          effectiveGasPrice: receipt.effectiveGasPrice,
          logs: receipt.logs,
        };
      } catch {
        // viem throws rather than returning null for an unknown hash. An unknown
        // hash means the outcome is not yet observable, not that it failed.
        return undefined;
      }
    },
    async getBlockHashAtNumber(blockNumber) {
      try {
        const block = await client.getBlock({ blockNumber, includeTransactions: false });
        return block.hash ?? undefined;
      } catch {
        return undefined;
      }
    },
    async getLatestBlockNumber() {
      return client.getBlockNumber({ cacheTime: 0 });
    },
    async getFinalizedBlockNumber() {
      try {
        const block = await client.getBlock({ blockTag: "finalized", includeTransactions: false });
        return block.number ?? undefined;
      } catch {
        return undefined;
      }
    },
  };
}

const sameAddress = (a: string, b: string): boolean => a.toLowerCase() === b.toLowerCase();

/**
 * Re-reads the chain and decides whether a settlement may release a service.
 *
 * @param reader Chain reads, bound to the RPC the profile allows.
 * @param profile Chain profile supplying the expected chain id and finality rule.
 * @param expected The payment that was authorized.
 * @returns A verdict. Only `final` permits delivery.
 */
export async function verifySettlement(
  reader: SettlementReader,
  profile: ChainProfile,
  expected: SettlementExpectation,
): Promise<SettlementVerdict> {
  const chainId = await reader.getChainId();
  if (chainId !== profile.chainId) {
    return {
      status: "mismatch",
      reason: `settlement was read from chain ${String(chainId)} but ${profile.caip2} was expected`,
    };
  }

  const receipt = await reader.getReceipt(expected.txHash);
  if (!receipt) {
    return { status: "pending-inclusion", reason: "no receipt for this transaction hash yet" };
  }
  // The node is not taken at its word about which transaction it answered with.
  if (receipt.transactionHash.toLowerCase() !== expected.txHash.toLowerCase()) {
    return {
      status: "mismatch",
      reason:
        `the receipt returned for ${expected.txHash} reports transaction hash ` +
        `${receipt.transactionHash}; refusing to treat it as this settlement`,
    };
  }
  if (receipt.status !== "success") {
    return { status: "reverted", reason: "the settlement transaction reverted; no transfer occurred" };
  }

  const canonicalHash = await reader.getBlockHashAtNumber(receipt.blockNumber);
  if (canonicalHash === undefined) {
    return {
      status: "pending-inclusion",
      reason: `block ${receipt.blockNumber.toString(10)} is not readable from this node yet`,
    };
  }
  if (canonicalHash.toLowerCase() !== receipt.blockHash.toLowerCase()) {
    return {
      status: "not-canonical",
      reason:
        `the receipt names block ${receipt.blockHash} at height ${receipt.blockNumber.toString(10)}, ` +
        `but the canonical block at that height is ${canonicalHash}; the receipt is stale`,
    };
  }

  const expectedAmount = BigInt(expected.amountAtomic);
  const transfers = receipt.logs
    .filter((log) => sameAddress(log.address, expected.asset))
    .flatMap((log) => {
      try {
        const decoded = decodeEventLog({ abi: [TRANSFER_EVENT], data: log.data, topics: log.topics });
        return [decoded.args];
      } catch {
        return [];
      }
    });

  const matching = transfers.filter(
    (transfer) =>
      sameAddress(transfer.from, expected.from) &&
      sameAddress(transfer.to, expected.to) &&
      transfer.value === expectedAmount,
  );
  if (matching.length === 0) {
    return {
      status: "mismatch",
      reason:
        `no Transfer of ${expected.amountAtomic} atomic units from the payer to the payee was emitted ` +
        `by ${expected.asset} in this transaction`,
    };
  }
  if (matching.length > 1) {
    return {
      status: "mismatch",
      reason: "the transaction emitted the expected transfer more than once; refusing to treat it as one payment",
    };
  }

  const authorizationUsed = receipt.logs
    .filter((log) => sameAddress(log.address, expected.asset))
    .some((log) => {
      try {
        const decoded = decodeEventLog({
          abi: [AUTHORIZATION_USED_EVENT],
          data: log.data,
          topics: log.topics,
        });
        return (
          sameAddress(decoded.args.authorizer, expected.from) &&
          decoded.args.nonce.toLowerCase() === expected.authorizationNonce.toLowerCase()
        );
      } catch {
        return false;
      }
    });
  if (!authorizationUsed) {
    return {
      status: "mismatch",
      reason:
        "the transaction did not consume the authorization nonce that was signed, so this settlement " +
        "is not the authorized payment",
    };
  }

  const latest = await reader.getLatestBlockNumber();
  const confirmations = latest >= receipt.blockNumber ? latest - receipt.blockNumber + 1n : 0n;

  const facts: SettlementFacts = {
    chainId,
    txHash: expected.txHash,
    blockNumber: receipt.blockNumber.toString(10),
    blockHash: receipt.blockHash,
    asset: expected.asset,
    from: expected.from,
    to: expected.to,
    amountAtomic: expected.amountAtomic,
    gasUsed: receipt.gasUsed.toString(10),
    effectiveGasPriceWei: receipt.effectiveGasPrice.toString(10),
    confirmations: confirmations.toString(10),
    finalityRule: profile.finality.kind,
    authorizationNonce: expected.authorizationNonce,
    verifiedAtUnix: Math.floor(Date.now() / 1000),
  };

  if (profile.finality.kind === "confirmations") {
    const required = BigInt(profile.finality.confirmations);
    if (confirmations < required) {
      return {
        status: "pending-finality",
        facts,
        reason: `${confirmations.toString(10)} of ${required.toString(10)} required confirmations`,
      };
    }
    return { status: "final", facts };
  }

  const finalized = await reader.getFinalizedBlockNumber();
  if (finalized === undefined) {
    return {
      status: "pending-finality",
      facts,
      reason: "the node served no finalized block tag, so finality cannot be established",
    };
  }
  if (receipt.blockNumber > finalized) {
    return {
      status: "pending-finality",
      facts,
      reason:
        `settlement is in block ${receipt.blockNumber.toString(10)} but the node's finalized head is ` +
        `${finalized.toString(10)}`,
    };
  }
  return { status: "final", facts };
}
