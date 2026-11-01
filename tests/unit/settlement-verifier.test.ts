import { describe, expect, it } from "vitest";
import { encodeEventTopics, parseEther, toHex } from "viem";
import { requireChainProfile, verifySettlement, type SettlementReader } from "@pulseagent/core";

const ASSET = "0x1111111111111111111111111111111111111111" as const;
const PAYER = "0x2222222222222222222222222222222222222222" as const;
const PAYEE = "0x3333333333333333333333333333333333333333" as const;
const OTHER = "0x4444444444444444444444444444444444444444" as const;
const TX = `0x${"aa".repeat(32)}` as const;
const BLOCK = `0x${"bb".repeat(32)}` as const;
const NONCE = `0x${"cc".repeat(32)}` as const;
const AMOUNT = "1500";

const TRANSFER_ABI = [
  {
    type: "event",
    name: "Transfer",
    inputs: [
      { name: "from", type: "address", indexed: true },
      { name: "to", type: "address", indexed: true },
      { name: "value", type: "uint256", indexed: false },
    ],
  },
] as const;

const AUTH_USED_ABI = [
  {
    type: "event",
    name: "AuthorizationUsed",
    inputs: [
      { name: "authorizer", type: "address", indexed: true },
      { name: "nonce", type: "bytes32", indexed: true },
    ],
  },
] as const;

function transferLog(args: { from?: `0x${string}`; to?: `0x${string}`; value?: bigint; address?: `0x${string}` } = {}) {
  return {
    address: args.address ?? ASSET,
    topics: encodeEventTopics({
      abi: TRANSFER_ABI,
      eventName: "Transfer",
      args: { from: args.from ?? PAYER, to: args.to ?? PAYEE },
    }),
    data: toHex(args.value ?? BigInt(AMOUNT), { size: 32 }),
    blockNumber: 10n,
    blockHash: BLOCK,
    logIndex: 0,
    transactionHash: TX,
    transactionIndex: 0,
    removed: false,
  } as never;
}

function authUsedLog(args: { authorizer?: `0x${string}`; nonce?: `0x${string}` } = {}) {
  return {
    address: ASSET,
    topics: encodeEventTopics({
      abi: AUTH_USED_ABI,
      eventName: "AuthorizationUsed",
      args: { authorizer: args.authorizer ?? PAYER, nonce: args.nonce ?? NONCE },
    }),
    data: "0x",
    blockNumber: 10n,
    blockHash: BLOCK,
    logIndex: 1,
    transactionHash: TX,
    transactionIndex: 0,
    removed: false,
  } as never;
}

interface ReaderOverrides {
  chainId?: number;
  receipt?: Parameters<typeof makeReader>[0]["receipt"];
  canonicalHash?: `0x${string}` | undefined;
  latest?: bigint;
  finalized?: bigint | undefined;
}

function makeReader(options: {
  chainId?: number;
  receipt?: {
    transactionHash?: `0x${string}`;
    status?: "success" | "reverted";
    blockNumber?: bigint;
    blockHash?: `0x${string}`;
    logs?: readonly unknown[];
  } | null;
  canonicalHash?: `0x${string}` | undefined;
  latest?: bigint;
  finalized?: bigint | undefined;
}): SettlementReader {
  return {
    async getChainId() {
      return options.chainId ?? 31_337;
    },
    async getReceipt() {
      if (options.receipt === null) return undefined;
      const receipt = options.receipt ?? {};
      return {
        transactionHash: receipt.transactionHash ?? TX,
        status: receipt.status ?? "success",
        blockNumber: receipt.blockNumber ?? 10n,
        blockHash: receipt.blockHash ?? BLOCK,
        gasUsed: 80_000n,
        effectiveGasPrice: parseEther("0.000000001"),
        logs: (receipt.logs ?? [transferLog(), authUsedLog()]) as never,
      };
    },
    async getBlockHashAtNumber() {
      return options.canonicalHash === undefined && !("canonicalHash" in options) ? BLOCK : options.canonicalHash;
    },
    async getLatestBlockNumber() {
      return options.latest ?? 11n;
    },
    async getFinalizedBlockNumber() {
      return "finalized" in options ? options.finalized : 10n;
    },
  };
}

const local = requireChainProfile("eip155:31337");
const testnet = requireChainProfile("eip155:943");
const expected = {
  txHash: TX,
  asset: ASSET,
  from: PAYER,
  to: PAYEE,
  amountAtomic: AMOUNT,
  authorizationNonce: NONCE,
} as const;

describe("independent settlement verification", () => {
  it("accepts an exact, canonical, confirmed settlement", async () => {
    const verdict = await verifySettlement(makeReader({}), local, expected);
    expect(verdict.status).toBe("final");
    if (verdict.status === "final") {
      expect(verdict.facts.amountAtomic).toBe(AMOUNT);
      expect(verdict.facts.authorizationNonce).toBe(NONCE);
      expect(verdict.facts.finalityRule).toBe("confirmations");
    }
  });

  it("refuses a receipt read from the wrong chain", async () => {
    const verdict = await verifySettlement(makeReader({ chainId: 1 }), local, expected);
    expect(verdict.status).toBe("mismatch");
    if (verdict.status === "mismatch") expect(verdict.reason).toMatch(/chain 1/);
  });

  it("refuses a receipt whose hash is not the one asked about", async () => {
    const verdict = await verifySettlement(
      makeReader({ receipt: { transactionHash: `0x${"dd".repeat(32)}` } }),
      local,
      expected,
    );
    expect(verdict.status).toBe("mismatch");
    if (verdict.status === "mismatch") expect(verdict.reason).toMatch(/reports transaction hash/);
  });

  it("treats a missing receipt as unknown, not as failure", async () => {
    // An unknown outcome must never be reported as a failure: that is what turns
    // a timeout into a second payment.
    const verdict = await verifySettlement(makeReader({ receipt: null }), local, expected);
    expect(verdict.status).toBe("pending-inclusion");
  });

  it("refuses a reverted transaction", async () => {
    const verdict = await verifySettlement(makeReader({ receipt: { status: "reverted" } }), local, expected);
    expect(verdict.status).toBe("reverted");
  });

  it("refuses a stale receipt whose block is no longer canonical", async () => {
    const verdict = await verifySettlement(
      makeReader({ canonicalHash: `0x${"ee".repeat(32)}` }),
      local,
      expected,
    );
    expect(verdict.status).toBe("not-canonical");
    if (verdict.status === "not-canonical") expect(verdict.reason).toMatch(/stale/);
  });

  it("refuses a settlement with no matching transfer", async () => {
    const verdict = await verifySettlement(makeReader({ receipt: { logs: [authUsedLog()] } }), local, expected);
    expect(verdict.status).toBe("mismatch");
  });

  it("refuses a transfer of the wrong amount, in either direction", async () => {
    for (const value of [1499n, 1501n, 0n]) {
      const verdict = await verifySettlement(
        makeReader({ receipt: { logs: [transferLog({ value }), authUsedLog()] } }),
        local,
        expected,
      );
      expect(verdict.status, `amount ${value.toString()}`).toBe("mismatch");
    }
  });

  it("refuses a transfer from or to the wrong party", async () => {
    const wrongFrom = await verifySettlement(
      makeReader({ receipt: { logs: [transferLog({ from: OTHER }), authUsedLog()] } }),
      local,
      expected,
    );
    expect(wrongFrom.status).toBe("mismatch");
    const wrongTo = await verifySettlement(
      makeReader({ receipt: { logs: [transferLog({ to: OTHER }), authUsedLog()] } }),
      local,
      expected,
    );
    expect(wrongTo.status).toBe("mismatch");
  });

  it("refuses a transfer emitted by a different token", async () => {
    const verdict = await verifySettlement(
      makeReader({ receipt: { logs: [transferLog({ address: OTHER }), authUsedLog()] } }),
      local,
      expected,
    );
    expect(verdict.status).toBe("mismatch");
  });

  it("refuses a settlement that did not consume the signed authorization", async () => {
    // A matching transfer alone only proves some transfer happened. Binding to
    // the nonce is what makes it provably the authorized payment.
    const noAuth = await verifySettlement(makeReader({ receipt: { logs: [transferLog()] } }), local, expected);
    expect(noAuth.status).toBe("mismatch");
    if (noAuth.status === "mismatch") expect(noAuth.reason).toMatch(/authorization nonce/);

    const otherNonce = await verifySettlement(
      makeReader({ receipt: { logs: [transferLog(), authUsedLog({ nonce: `0x${"11".repeat(32)}` })] } }),
      local,
      expected,
    );
    expect(otherNonce.status).toBe("mismatch");
  });

  it("refuses a transaction that emitted the expected transfer twice", async () => {
    const verdict = await verifySettlement(
      makeReader({ receipt: { logs: [transferLog(), transferLog(), authUsedLog()] } }),
      local,
      expected,
    );
    expect(verdict.status).toBe("mismatch");
    if (verdict.status === "mismatch") expect(verdict.reason).toMatch(/more than once/);
  });

  it("reports insufficient confirmations as pending, not final", async () => {
    const verdict = await verifySettlement(makeReader({ latest: 9n }), local, expected);
    expect(verdict.status).toBe("pending-finality");
    if (verdict.status === "pending-finality") expect(verdict.facts.confirmations).toBe("0");
  });

  it("requires the finalized tag on a public chain and stays pending behind it", async () => {
    const behind = await verifySettlement(makeReader({ chainId: 943, finalized: 9n, latest: 200n }), testnet, expected);
    expect(behind.status).toBe("pending-finality");
    if (behind.status === "pending-finality") expect(behind.reason).toMatch(/finalized head/);

    // A long finality lag must leave the settlement resumable rather than failed,
    // and must not re-test the authorization's expiry after inclusion.
    const final = await verifySettlement(makeReader({ chainId: 943, finalized: 10n, latest: 200n }), testnet, expected);
    expect(final.status).toBe("final");

    const noTag = await verifySettlement(
      makeReader({ chainId: 943, finalized: undefined, latest: 200n }),
      testnet,
      expected,
    );
    expect(noTag.status).toBe("pending-finality");
    if (noTag.status === "pending-finality") expect(noTag.reason).toMatch(/no finalized block tag/);
  });
});
