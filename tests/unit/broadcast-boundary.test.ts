import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Hex, PublicClient, WalletClient } from "viem";
import { AuditLog, DurableStore } from "@pulseagent/core";
import {
  BroadcastRefusedError,
  createConstrainedWriter,
  withSettlementConstraint,
} from "@pulseagent/facilitator";

/**
 * The facilitator's broadcast boundary.
 *
 * Upstream decides what to submit; this decides whether it may be submitted at
 * all, with what gas, and whether it has been submitted already. The account
 * behind it holds native gas, and the buyer-side signer's gas reservation says
 * nothing about it, so every gate here is tested directly.
 */

const ASSET = "0x1111111111111111111111111111111111111111" as const;
const OTHER_ASSET = "0x9999999999999999999999999999999999999999" as const;
const PAYER = "0x2222222222222222222222222222222222222222" as const;
const PAYEE = "0x3333333333333333333333333333333333333333" as const;
const ATTACKER = "0x4444444444444444444444444444444444444444" as const;
const FACILITATOR = "0x5555555555555555555555555555555555555555" as const;
const NONCE = `0x${"aa".repeat(32)}` as const;

const stores: DurableStore[] = [];
afterEach(() => {
  while (stores.length > 0) stores.pop()?.close();
});

interface FakeChain {
  pendingNonce: number;
  readonly signedNonces: number[];
  readonly sentNonces: number[];
  // Explicitly nullable: these are cleared again after a test arms them, and
  // `exactOptionalPropertyTypes` distinguishes "absent" from "set to undefined".
  failSendFrom?: number | undefined;
  failSignFrom?: number | undefined;
}

function harness(options: { pendingNonce?: number; feePerGas?: bigint; totalFeeBudgetWei?: bigint } = {}) {
  const chain: FakeChain = { pendingNonce: options.pendingNonce ?? 0, signedNonces: [], sentNonces: [] };
  const databasePath = path.join(mkdtempSync(path.join(tmpdir(), "pa-broadcast-")), "state.sqlite");
  const store = DurableStore.open(databasePath);
  stores.push(store);

  const publicClient = {
    async getTransactionCount() {
      return chain.pendingNonce;
    },
    async estimateContractGas() {
      return 80_000n;
    },
    async estimateFeesPerGas() {
      return { maxFeePerGas: options.feePerGas ?? 1_000_000_000n, maxPriorityFeePerGas: 100_000_000n };
    },
    async sendRawTransaction({ serializedTransaction }: { serializedTransaction: Hex }) {
      const nonce = Number(serializedTransaction.slice(-8));
      if (chain.failSendFrom !== undefined && chain.sentNonces.length >= chain.failSendFrom) {
        throw new Error("network refused the transaction");
      }
      chain.sentNonces.push(nonce);
      return serializedTransaction;
    },
    async waitForTransactionReceipt() {
      return { status: "success", logs: [] };
    },
  } as unknown as PublicClient;

  const walletClient = {
    account: { address: FACILITATOR },
    async signTransaction(args: { nonce: number }) {
      if (chain.failSignFrom !== undefined && chain.signedNonces.length >= chain.failSignFrom) {
        throw new Error("signing failed");
      }
      chain.signedNonces.push(args.nonce);
      // Deterministic in the nonce, so a hash identifies which nonce was signed.
      return `0x${args.nonce.toString(16).padStart(8, "0").repeat(16)}${String(args.nonce).padStart(8, "0")}` as Hex;
    },
  } as unknown as WalletClient;

  const writer = createConstrainedWriter({
    publicClient,
    walletClient,
    address: FACILITATOR,
    chainId: 31_337,
    network: "eip155:31337",
    allowedAssets: [ASSET],
    allowedPayees: [PAYEE],
    limits: {
      maxGasLimit: 300_000n,
      maxFeePerGasWei: 5_000_000_000n,
      maxPriorityFeePerGasWei: 2_000_000_000n,
      totalFeeBudgetWei: options.totalFeeBudgetWei ?? 10n ** 18n,
    },
    store,
    audit: new AuditLog(store),
    facilitatorId: "facilitator-test",
    policyRevision: "fac-rev-1",
  });

  return { chain, store, writer };
}

function transferArgs(overrides: { to?: string; value?: bigint; nonce?: string; from?: string } = {}) {
  return [
    overrides.from ?? PAYER,
    overrides.to ?? PAYEE,
    overrides.value ?? 1500n,
    0n,
    BigInt(Math.floor(Date.now() / 1000) + 300),
    overrides.nonce ?? NONCE,
    27,
    `0x${"11".repeat(32)}`,
    `0x${"22".repeat(32)}`,
  ] as const;
}

const constraint = { asset: ASSET, payTo: PAYEE, amountAtomic: "1500", network: "eip155:31337" } as const;

async function broadcast(
  writer: ReturnType<typeof createConstrainedWriter>,
  overrides: Parameters<typeof transferArgs>[0] = {},
  address: `0x${string}` = ASSET,
): Promise<Hex> {
  return withSettlementConstraint(constraint, () =>
    writer.writeContract({ address, abi: [], functionName: "transferWithAuthorization", args: transferArgs(overrides) }),
  );
}

describe("constrained broadcast", () => {
  it("submits an allowed settlement once", async () => {
    const { writer, chain } = harness();
    const hash = await broadcast(writer);
    expect(hash).toMatch(/^0x/);
    expect(chain.sentNonces).toEqual([0]);
  });

  it("refuses anything but a transfer authorization", async () => {
    const { writer } = harness();
    await expect(
      withSettlementConstraint(constraint, () =>
        writer.writeContract({ address: ASSET, abi: [], functionName: "approve", args: [PAYEE, 1n] }),
      ),
    ).rejects.toThrow(/only transferWithAuthorization/);
  });

  it("refuses a raw transaction outright", async () => {
    const { writer } = harness();
    await expect(writer.sendTransaction({ to: ASSET, data: "0xdeadbeef" })).rejects.toThrow(
      /does not submit raw transactions/,
    );
  });

  it("refuses a broadcast with no declared settlement constraint", async () => {
    const { writer } = harness();
    await expect(
      writer.writeContract({ address: ASSET, abi: [], functionName: "transferWithAuthorization", args: transferArgs() }),
    ).rejects.toThrow(BroadcastRefusedError);
  });

  it("refuses an asset outside the allowlist, and one the settlement is not for", async () => {
    const { writer } = harness();
    await expect(broadcast(writer, {}, OTHER_ASSET)).rejects.toThrow(/not an allowlisted asset/);
    await expect(
      withSettlementConstraint({ ...constraint, asset: OTHER_ASSET }, () =>
        writer.writeContract({
          address: ASSET,
          abi: [],
          functionName: "transferWithAuthorization",
          args: transferArgs(),
        }),
      ),
    ).rejects.toThrow(/not the asset this settlement is for/);
  });

  it("refuses a payee the operator has not allowlisted", async () => {
    // A valid authorization settled to an attacker's address still spends this
    // facilitator's gas, so the payee is operator configuration.
    const { writer } = harness();
    await expect(
      withSettlementConstraint({ ...constraint, payTo: ATTACKER }, () =>
        writer.writeContract({
          address: ASSET,
          abi: [],
          functionName: "transferWithAuthorization",
          args: transferArgs({ to: ATTACKER }),
        }),
      ),
    ).rejects.toThrow(/not an operator-allowlisted recipient/);
  });

  it("refuses a payee or amount that is not the one the settlement names", async () => {
    const { writer } = harness();
    await expect(broadcast(writer, { to: ATTACKER })).rejects.toThrow(/not the payee this settlement names/);
    await expect(broadcast(writer, { value: 1501n })).rejects.toThrow(/not the amount this settlement names/);
  });

  it("refuses appended calldata", async () => {
    const { writer } = harness();
    await expect(
      withSettlementConstraint(constraint, () =>
        writer.writeContract({
          address: ASSET,
          abi: [],
          functionName: "transferWithAuthorization",
          args: transferArgs(),
          dataSuffix: "0xdeadbeef",
        }),
      ),
    ).rejects.toThrow(/appended calldata/);
  });

  it("refuses a fee above the configured cap", async () => {
    const { writer } = harness({ feePerGas: 9_000_000_000n });
    await expect(broadcast(writer)).rejects.toThrow(/exceeds the configured cap/);
  });

  it("refuses once the lifetime fee budget is spent", async () => {
    // Worst-case fee per broadcast here is 96,000 gas at 1 gwei, so this budget
    // covers two and must refuse the third rather than draining the account.
    const { writer, chain } = harness({ totalFeeBudgetWei: 250_000_000_000_000n });
    let refusals = 0;
    for (let index = 0; index < 5; index += 1) {
      try {
        await broadcast(writer, { nonce: `0x${index.toString(16).padStart(2, "0").repeat(32)}` });
      } catch (error) {
        if (error instanceof BroadcastRefusedError && error.code === "budget_exhausted") refusals += 1;
        else throw error;
      }
    }
    expect(refusals).toBeGreaterThan(0);
    expect(chain.sentNonces).toEqual([0, 1]);
  });

  it("broadcasts one authorization once, returning the recorded hash on a repeat", async () => {
    const { writer, chain } = harness();
    const first = await broadcast(writer);
    const repeat = await broadcast(writer);
    expect(repeat).toBe(first);
    expect(chain.sentNonces).toEqual([0]);
  });

  it("refuses to reuse a claimed slot for different terms", async () => {
    const { writer } = harness();
    await broadcast(writer);
    await expect(
      withSettlementConstraint({ ...constraint, amountAtomic: "2500" }, () =>
        writer.writeContract({
          address: ASSET,
          abi: [],
          functionName: "transferWithAuthorization",
          args: transferArgs({ value: 2500n }),
        }),
      ),
    ).rejects.toThrow(/different asset, payee or amount terms/);
  });

  it("scopes a nonce to its token, since EIP-3009 nonces are per token", async () => {
    const { writer, chain } = harness();
    const base = await broadcast(writer);
    // A different asset with the same payer and nonce is a different
    // authorization and must not be deduplicated onto the first.
    const second = createConstrainedWriter({
      publicClient: {
        async getTransactionCount() {
          return chain.pendingNonce;
        },
        async estimateContractGas() {
          return 80_000n;
        },
        async estimateFeesPerGas() {
          return { maxFeePerGas: 1_000_000_000n, maxPriorityFeePerGas: 100_000_000n };
        },
        async sendRawTransaction() {
          return "0x";
        },
        async waitForTransactionReceipt() {
          return { status: "success", logs: [] };
        },
      } as unknown as PublicClient,
      walletClient: {
        account: { address: FACILITATOR },
        async signTransaction(args: { nonce: number }) {
          return `0x${"ff".repeat(32)}${String(args.nonce)}` as Hex;
        },
      } as unknown as WalletClient,
      address: FACILITATOR,
      chainId: 31_337,
      network: "eip155:31337",
      allowedAssets: [OTHER_ASSET],
      allowedPayees: [PAYEE],
      limits: {
        maxGasLimit: 300_000n,
        maxFeePerGasWei: 5_000_000_000n,
        maxPriorityFeePerGasWei: 2_000_000_000n,
        totalFeeBudgetWei: 10n ** 18n,
      },
      store: stores[stores.length - 1]!,
      audit: new AuditLog(stores[stores.length - 1]!),
      facilitatorId: "facilitator-test",
      policyRevision: "fac-rev-1",
    });
    const other = await withSettlementConstraint({ ...constraint, asset: OTHER_ASSET }, () =>
      second.writeContract({
        address: OTHER_ASSET,
        abi: [],
        functionName: "transferWithAuthorization",
        args: transferArgs(),
      }),
    );
    expect(other).not.toBe(base);
  });
});

describe("sender nonce sequence", () => {
  it("leaves no gap when concurrent duplicates race for one authorization", async () => {
    // Executed review finding: the losing duplicate allocated a nonce before its
    // claim failed, so the next real payment skipped one and every later
    // transaction from this account queued behind a nonce nothing would ever use.
    const { writer, chain } = harness();
    const racers = await Promise.allSettled([broadcast(writer), broadcast(writer), broadcast(writer)]);
    expect(racers.every((outcome) => outcome.status === "fulfilled")).toBe(true);
    expect(new Set(racers.map((outcome) => (outcome.status === "fulfilled" ? outcome.value : "")))).toHaveLength(1);

    // The next distinct authorization must follow immediately, with no gap.
    chain.pendingNonce = 1;
    await broadcast(writer, { nonce: `0x${"bb".repeat(32)}` });
    expect(chain.sentNonces).toEqual([0, 1]);
  });

  it("gives concurrent distinct authorizations consecutive nonces", async () => {
    const { writer, chain } = harness();
    await Promise.all([
      broadcast(writer, { nonce: `0x${"c1".repeat(32)}` }),
      broadcast(writer, { nonce: `0x${"c2".repeat(32)}` }),
      broadcast(writer, { nonce: `0x${"c3".repeat(32)}` }),
    ]);
    expect([...chain.sentNonces].sort((a, b) => a - b)).toEqual([0, 1, 2]);
  });

  it("reuses the same nonce after a signing failure, rather than skipping one", async () => {
    const { writer, chain } = harness();
    chain.failSignFrom = 0;
    await expect(broadcast(writer)).rejects.toThrow(/signing failed/);
    chain.failSignFrom = undefined;
    // The retry must rebuild the same transaction on the same nonce.
    await broadcast(writer);
    expect(chain.signedNonces).toEqual([0]);
    expect(chain.sentNonces).toEqual([0]);
  });

  it("keeps the recorded hash when the send itself fails, so nothing is sent twice", async () => {
    const { writer, chain } = harness();
    chain.failSendFrom = 0;
    await expect(broadcast(writer)).rejects.toThrow(/network refused/);
    chain.failSendFrom = undefined;
    // The outcome was unknown, so the same transaction is what a retry returns.
    const retry = await broadcast(writer);
    expect(retry).toMatch(/^0x/);
    expect(chain.signedNonces).toEqual([0]);
  });
});
