import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { startSigner, type RunningSigner } from "@pulseagent/signer";
import type { PaymentPolicy } from "@pulseagent/core";

/**
 * Regressions against the real signer over HTTP.
 *
 * These exercise the actual service, not the validation function: the executed
 * review finding that one intent could yield three spendable signatures passed
 * every unit-level check and only appeared at this boundary.
 */

const ASSET = "0x1111111111111111111111111111111111111111";
const PAYEE = "0x2222222222222222222222222222222222222222";

const running: RunningSigner[] = [];
afterEach(async () => {
  while (running.length > 0) await running.pop()?.close();
});

function policyFor(overrides: Partial<PaymentPolicy> = {}): PaymentPolicy {
  return {
    principalId: "buyer-a",
    policyRevision: "rev-1",
    network: "eip155:31337",
    allowedServiceOrigins: ["http://127.0.0.1:8080"],
    allowedResourcePaths: ["/digest"],
    allowedPayees: [PAYEE],
    allowedAssets: [
      {
        address: ASSET,
        symbol: "PAVT",
        decimals: 6,
        eip712Name: "Test Token",
        eip712Version: "1",
        assetTransferMethod: "eip3009",
        valuelessTestFixture: true,
      },
    ],
    maxAmountPerPayment: "100",
    totalBudget: "200",
    maxGasReservationWei: "1000",
    totalGasBudgetWei: "100000",
    maxQuoteTtlSeconds: 300,
    maxRequestBodyBytes: 4096,
    ...overrides,
  };
}

async function start(
  policy: PaymentPolicy,
): Promise<{ signer: RunningSigner; token: string; databasePath: string }> {
  const token = randomBytes(32).toString("hex");
  const databasePath = path.join(mkdtempSync(path.join(tmpdir(), "pa-signer-")), "signer.sqlite");
  const signer = await startSigner({ policy, databasePath, authToken: token });
  running.push(signer);
  return { signer, token, databasePath };
}

function body(signer: RunningSigner, overrides: { nonce?: string; intentId?: string; idempotencyKey?: string; amount?: string } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const amount = overrides.amount ?? "100";
  return {
    intentId: overrides.intentId ?? "int_cccccccccc",
    idempotencyKey: overrides.idempotencyKey ?? "idem_dddddddddd",
    principalId: "buyer-a",
    quote: {
      quoteId: "quote_aaaaaaaaaa",
      serviceOrigin: "http://127.0.0.1:8080",
      resourcePath: "/digest",
      requestDigest: `sha256:${"b".repeat(64)}`,
      network: "eip155:31337",
      asset: ASSET,
      assetDecimals: 6,
      payTo: PAYEE,
      amount,
      expiresAt: now + 120,
      eip712Name: "Test Token",
      eip712Version: "1",
      assetTransferMethod: "eip3009",
      maxTimeoutSeconds: 120,
    },
    typedData: {
      primaryType: "TransferWithAuthorization",
      domain: { name: "Test Token", version: "1", chainId: 31_337, verifyingContract: ASSET },
      message: {
        from: signer.address,
        to: PAYEE,
        value: amount,
        validAfter: "0",
        validBefore: String(now + 120),
        nonce: overrides.nonce ?? `0x${"01".repeat(32)}`,
      },
    },
  };
}

async function authorize(
  signer: RunningSigner,
  token: string,
  overrides: Parameters<typeof body>[1] = {},
): Promise<{ status: number; code?: string; signatureDigest?: string; signature?: string }> {
  const response = await fetch(`${signer.url}/authorize`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(body(signer, overrides)),
  });
  const payload = (await response.json()) as { code?: string; signatureDigest?: string; signature?: string };
  return { status: response.status, ...payload };
}

describe("signer transport", () => {
  it("exposes only a public address and refuses an unauthenticated caller", async () => {
    const { signer, token } = await start(policyFor());

    const anonymous = await fetch(`${signer.url}/health`);
    expect(anonymous.status).toBe(401);

    const health = await fetch(`${signer.url}/health`, { headers: { authorization: `Bearer ${token}` } });
    const payload = (await health.json()) as Record<string, unknown>;
    expect(payload["address"]).toMatch(/^0x[0-9a-fA-F]{40}$/);
    // No field may carry key material, and none of these endpoints exist.
    expect(JSON.stringify(payload)).not.toMatch(/0x[0-9a-fA-F]{64,}/);
    for (const route of ["/key", "/export", "/sign", "/signTypedData", "/policy"]) {
      const probe = await fetch(`${signer.url}${route}`, { headers: { authorization: `Bearer ${token}` } });
      expect(probe.status, route).toBe(404);
    }
  });

  it("refuses a request carrying an unknown field", async () => {
    const { signer, token } = await start(policyFor());
    const response = await fetch(`${signer.url}/authorize`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ ...body(signer), approved: true, maxAmountPerPayment: "999999" }),
    });
    expect(response.status).toBe(400);
    // A caller-supplied approval flag must carry no authority and no silent acceptance.
    expect((await response.json()) as unknown).toMatchObject({ reason: "schema_rejected" });
  });
});

describe("one intent, one spendable authorization", () => {
  it("refuses a second authorization for the same intent when only the nonce changes", async () => {
    // Executed review finding: three requests with identical intent and
    // idempotency ids but distinct nonces each returned a distinct signature,
    // authorizing 300 units against a 100-unit reservation.
    const { signer, token } = await start(policyFor());
    const first = await authorize(signer, token, { nonce: `0x${"01".repeat(32)}` });
    const second = await authorize(signer, token, { nonce: `0x${"02".repeat(32)}` });
    const third = await authorize(signer, token, { nonce: `0x${"03".repeat(32)}` });

    expect(first.status).toBe(200);
    expect(second.status).toBe(409);
    expect(second.code).toBe("authorization_already_bound");
    expect(third.status).toBe(409);
    const issued = new Set([first, second, third].flatMap((r) => (r.signatureDigest ? [r.signatureDigest] : [])));
    expect(issued.size).toBe(1);
  });

  it("returns byte-identical bytes for an exact retry", async () => {
    const { signer, token } = await start(policyFor());
    const first = await authorize(signer, token);
    const retry = await authorize(signer, token);
    expect(first.status).toBe(200);
    expect(retry.status).toBe(200);
    expect(retry.signature).toBe(first.signature);
    expect(retry.signatureDigest).toBe(first.signatureDigest);
  });

  it("honours an exact retry even when the first payment filled the budget", async () => {
    // Executed review finding: with the budget exactly consumed, the identical
    // retry was refused as budget_exhausted, stranding a legitimate recovery.
    const { signer, token } = await start(policyFor({ totalBudget: "100", maxAmountPerPayment: "100" }));
    const first = await authorize(signer, token);
    const retry = await authorize(signer, token);
    expect(first.status).toBe(200);
    expect(retry.status).toBe(200);
    expect(retry.signature).toBe(first.signature);
  });

  it("issues exactly one signature under concurrent distinct-nonce requests", async () => {
    const { signer, token } = await start(policyFor());
    const outcomes = await Promise.all(
      [`0x${"0a".repeat(32)}`, `0x${"0b".repeat(32)}`, `0x${"0c".repeat(32)}`].map((nonce) =>
        authorize(signer, token, { nonce }),
      ),
    );
    const issued = new Set(outcomes.flatMap((r) => (r.signatureDigest ? [r.signatureDigest] : [])));
    expect(issued.size).toBe(1);
    expect(outcomes.filter((r) => r.status === 200)).toHaveLength(1);
  });

  it("refuses reusing a nonce under a different intent", async () => {
    const { signer, token } = await start(policyFor());
    expect((await authorize(signer, token)).status).toBe(200);
    const stolen = await authorize(signer, token, { intentId: "int_eeeeeeeeee", idempotencyKey: "idem_ffffffffff" });
    expect(stolen.status).toBe(409);
    expect(stolen.code).toBe("nonce_bound_to_other_intent");
  });

  it("enforces the per-payment ceiling and the total budget", async () => {
    const { signer, token } = await start(policyFor());
    const tooLarge = await authorize(signer, token, { amount: "101", nonce: `0x${"11".repeat(32)}` });
    expect(tooLarge.status).toBe(403);
    expect(tooLarge.code).toBe("amount_over_per_payment_limit");

    expect((await authorize(signer, token, { intentId: "int_1111111111", idempotencyKey: "idem_1111111111", nonce: `0x${"21".repeat(32)}` })).status).toBe(200);
    expect((await authorize(signer, token, { intentId: "int_2222222222", idempotencyKey: "idem_2222222222", nonce: `0x${"22".repeat(32)}` })).status).toBe(200);
    const beyond = await authorize(signer, token, {
      intentId: "int_3333333333",
      idempotencyKey: "idem_3333333333",
      nonce: `0x${"23".repeat(32)}`,
    });
    expect(beyond.status).toBe(403);
    expect(beyond.code).toBe("budget_exhausted");
  });

  it("keeps every audit record free of signature material", async () => {
    const { signer, token, databasePath } = await start(policyFor());
    await authorize(signer, token);
    const { DurableStore, AuditLog } = await import("@pulseagent/core");
    const store = DurableStore.open(databasePath);
    try {
      const events = new AuditLog(store).read();
      expect(events.length).toBeGreaterThan(0);
      expect(JSON.stringify(events)).not.toMatch(/0x[0-9a-fA-F]{130,}/);
      expect(events.some((event) => event.kind === "signer.authorization.signed")).toBe(true);
    } finally {
      store.close();
    }
  });
});
