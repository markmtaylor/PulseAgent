import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { authorizationConsumed, tokenBalance } from "@pulseagent/localchain";
import { startLocalStack, type LocalStack } from "@pulseagent/two-agents";

/**
 * The whole stack: a disposable chain, the fixture token, and the signer,
 * facilitator and seller as separate processes with a buyer client driving them.
 *
 * Nothing is mocked. These tests pass only if a payment really settled on chain
 * and the buyer really verified it.
 */

const stacks: LocalStack[] = [];
afterEach(async () => {
  while (stacks.length > 0) await stacks.pop()?.stop();
});

async function start(options: Parameters<typeof startLocalStack>[0] extends infer T ? Partial<T> : never = {}) {
  const stack = await startLocalStack({
    runtimeDir: path.join(mkdtempSync(path.join(tmpdir(), "pa-stack-")), "runtime"),
    priceAtomic: "1500",
    payerFundingAtomic: "1000000",
    ...options,
  } as Parameters<typeof startLocalStack>[0]);
  stacks.push(stack);
  return stack;
}

const INPUT = "integration test input";
const sha256 = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");

async function payOnce(stack: LocalStack, input = INPUT, idempotencyKey = "idem_integration_0001") {
  const { quote, service } = await stack.client.requestQuote({ serviceOrigin: stack.sellerOrigin, input });
  const payment = await stack.client.requestPayment({
    quote,
    input,
    idempotencyKey,
    serviceName: service.name,
  });
  return { quote, service, payment };
}

/** Rewrites a stored claim, standing in for a corrupted or tampered record. */
function overwriteClaim(databasePath: string, namespace: string, key: string, value: string): void {
  const db = new DatabaseSync(databasePath);
  try {
    const digest = createHash("sha256").update(key, "utf8").digest("hex");
    const updated = db
      .prepare("UPDATE claims SET value = ? WHERE namespace = ? AND key = ?")
      .run(value, namespace, key);
    if (updated.changes === 0) {
      // Seller delivery claims are keyed by a digest the test does not recompute;
      // fall back to matching the single row in that namespace.
      db.prepare("UPDATE claims SET value = ? WHERE namespace = ?").run(value, namespace);
    }
    void digest;
  } finally {
    db.close();
  }
}

describe("two-agent payment", () => {
  it("settles once on chain and delivers a verified result", async () => {
    const stack = await start();
    const payerBefore = await tokenBalance(stack.chain, stack.token, stack.payerAddress);
    const payeeBefore = await tokenBalance(stack.chain, stack.token, stack.payeeAddress);

    const { payment } = await payOnce(stack);

    expect(payment.state).toBe("DELIVERED");
    expect(payment.result.sha256).toBe(sha256(INPUT));
    expect(payment.settlement.amountAtomic).toBe("1500");
    expect(payment.settlement.finalityRule).toBe("confirmations");

    // Exact movement, both sides, for a token with no transfer fee.
    expect(payerBefore - (await tokenBalance(stack.chain, stack.token, stack.payerAddress))).toBe(1500n);
    expect((await tokenBalance(stack.chain, stack.token, stack.payeeAddress)) - payeeBefore).toBe(1500n);
    expect(
      await authorizationConsumed(
        stack.chain,
        stack.token,
        stack.payerAddress,
        payment.settlement.authorizationNonce as `0x${string}`,
      ),
    ).toBe(true);
  });

  it("charges the payer nothing beyond the quoted amount in native gas", async () => {
    // Under EIP-3009 the facilitator sponsors gas; the payer holds no native
    // balance at all, which this asserts rather than assumes.
    const stack = await start();
    const { createPublicClient, http } = await import("viem");
    const { localChainDefinition } = await import("@pulseagent/localchain");
    const client = createPublicClient({
      chain: localChainDefinition(stack.chain),
      transport: http(stack.chain.url),
    });
    await payOnce(stack);
    expect(await client.getBalance({ address: stack.payerAddress })).toBe(0n);
  });

  it("returns the same result and receipt on a replay, charging nothing further", async () => {
    const stack = await start();
    const { quote, service, payment } = await payOnce(stack);
    const payeeAfterFirst = await tokenBalance(stack.chain, stack.token, stack.payeeAddress);

    const replay = await stack.client.requestPayment({
      quote,
      input: INPUT,
      idempotencyKey: "idem_integration_0001",
      serviceName: service.name,
    });
    expect(replay.resultDigest).toBe(payment.resultDigest);
    expect(replay.settlement.txHash).toBe(payment.settlement.txHash);
    expect(replay.replayed).toBe(true);
    expect(await tokenBalance(stack.chain, stack.token, stack.payeeAddress)).toBe(payeeAfterFirst);
  });

  it("settles at most once under concurrent duplicates, and both callers succeed", async () => {
    const stack = await start();
    const { quote, service } = await stack.client.requestQuote({
      serviceOrigin: stack.sellerOrigin,
      input: INPUT,
    });
    const attempt = () =>
      stack.client.requestPayment({ quote, input: INPUT, idempotencyKey: "idem_race_0001", serviceName: service.name });

    const outcomes = await Promise.allSettled([attempt(), attempt(), attempt()]);
    const fulfilled = outcomes.flatMap((outcome) => (outcome.status === "fulfilled" ? [outcome.value] : []));
    expect(fulfilled.length).toBe(3);
    expect(new Set(fulfilled.map((payment) => payment.settlement.txHash)).size).toBe(1);
    expect(await tokenBalance(stack.chain, stack.token, stack.payeeAddress)).toBe(1500n);
  });

  it("refuses a changed body under the same intent, rather than answering from cache", async () => {
    const stack = await start();
    const { quote, service } = await payOnce(stack);
    await expect(
      stack.client.requestPayment({
        quote,
        input: `${INPUT} changed`,
        idempotencyKey: "idem_integration_0001",
        serviceName: service.name,
      }),
    ).rejects.toThrow(/request_digest_mismatch|different request body|does not price/);
  });

  it("refuses a changed body even when the quote digest is recomputed to match", async () => {
    const stack = await start();
    const { quote, service } = await payOnce(stack);
    const { serviceRequestDigest } = await import("@pulseagent/core");
    const forged = {
      ...quote,
      requestDigest: serviceRequestDigest({
        service: service.name,
        resourcePath: quote.resourcePath,
        input: `${INPUT} changed`,
      }),
    };
    await expect(
      stack.client.requestPayment({
        quote: forged,
        input: `${INPUT} changed`,
        idempotencyKey: "idem_integration_0001",
        serviceName: service.name,
      }),
    ).rejects.toThrow(/different quote terms|different request body/);
  });

  it("refuses a request whose body does not match the quote at the seller", async () => {
    const stack = await start();
    const { quote } = await stack.client.requestQuote({ serviceOrigin: stack.sellerOrigin, input: INPUT });
    const response = await fetch(`${stack.sellerOrigin}/digest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ quoteId: quote.quoteId, input: `${INPUT} tampered` }),
    });
    expect(response.status).toBe(409);
    const unknown = await fetch(`${stack.sellerOrigin}/digest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ quoteId: "quote_000000000000", input: INPUT }),
    });
    expect(unknown.status).toBe(404);
  });
});

describe("recovery", () => {
  it("collects a paid-for result after the quote has expired", async () => {
    // A payment that settled has been made. Refusing its retry because the quote
    // has since lapsed would take the money and withhold the result.
    const stack = await start({ quoteTtlSeconds: 6 });
    const { quote, service, payment } = await payOnce(stack, INPUT, "idem_expiry_0001");

    await new Promise((resolve) => setTimeout(resolve, 7000));
    expect(quote.expiresAt * 1000).toBeLessThan(Date.now());

    const recovered = await stack.client.requestPayment({
      quote,
      input: INPUT,
      idempotencyKey: "idem_expiry_0001",
      serviceName: service.name,
    });
    expect(recovered.settlement.txHash).toBe(payment.settlement.txHash);
    expect(recovered.result.sha256).toBe(sha256(INPUT));
    // And a *new* payment on the lapsed quote is still refused.
    await expect(
      stack.client.requestPayment({
        quote,
        input: INPUT,
        idempotencyKey: "idem_expiry_0002",
        serviceName: service.name,
      }),
    ).rejects.toThrow(/quote/i);
  });

  it("recovers from the seller's receipt when the paid response is lost", async () => {
    const stack = await start();
    const { quote, service, payment } = await payOnce(stack, INPUT, "idem_lost_0001");

    // Drop this client's own cache, leaving only the durable intent. That is the
    // state a crash between settlement and delivery leaves behind.
    const db = new DatabaseSync(stack.platformDatabasePath);
    try {
      db.prepare("DELETE FROM claims WHERE namespace = ?").run("buyer-delivery");
    } finally {
      db.close();
    }

    const recovered = await stack.client.requestPayment({
      quote,
      input: INPUT,
      idempotencyKey: "idem_lost_0001",
      serviceName: service.name,
    });
    expect(recovered.replayed).toBe(true);
    expect(recovered.settlement.txHash).toBe(payment.settlement.txHash);
    // Still one payment.
    expect(await tokenBalance(stack.chain, stack.token, stack.payeeAddress)).toBe(1500n);
  });

  it("withholds a recovered result that is not the digest of the paid-for input", async () => {
    // Executed review finding: a schema-valid result with the wrong digest was
    // returned as DELIVERED by the recovery path.
    const stack = await start();
    const { quote, service } = await payOnce(stack, INPUT, "idem_corrupt_0001");

    const db = new DatabaseSync(stack.platformDatabasePath);
    try {
      db.prepare("DELETE FROM claims WHERE namespace = ?").run("buyer-delivery");
      const row = db.prepare("SELECT key, value FROM claims WHERE namespace = 'delivery'").get() as
        | { key: string; value: string }
        | undefined;
      expect(row).toBeDefined();
      const record = JSON.parse(row!.value) as { result: { sha256: string } };
      record.result.sha256 = sha256("something else entirely");
      db.prepare("UPDATE claims SET value = ? WHERE namespace = 'delivery' AND key = ?").run(
        JSON.stringify(record),
        row!.key,
      );
    } finally {
      db.close();
    }

    await expect(
      stack.client.requestPayment({
        quote,
        input: INPUT,
        idempotencyKey: "idem_corrupt_0001",
        serviceName: service.name,
      }),
    ).rejects.toThrow(/not the digest of the paid-for input/);
  });

  it("withholds a cached result that is not the digest of the paid-for input", async () => {
    const stack = await start();
    const { quote, service, payment } = await payOnce(stack, INPUT, "idem_cache_0001");

    const db = new DatabaseSync(stack.platformDatabasePath);
    try {
      const row = db.prepare("SELECT key, value FROM claims WHERE namespace = 'buyer-delivery'").get() as
        | { key: string; value: string }
        | undefined;
      expect(row).toBeDefined();
      const record = JSON.parse(row!.value) as { result: { sha256: string } };
      record.result.sha256 = sha256("not what was paid for");
      db.prepare("UPDATE claims SET value = ? WHERE namespace = 'buyer-delivery' AND key = ?").run(
        JSON.stringify(record),
        row!.key,
      );
    } finally {
      db.close();
    }

    await expect(
      stack.client.requestPayment({
        quote,
        input: INPUT,
        idempotencyKey: "idem_cache_0001",
        serviceName: service.name,
      }),
    ).rejects.toThrow(/not the digest of the paid-for input/);
    void payment;
  });

  it("re-verifies a settlement on request without paying again", async () => {
    const stack = await start();
    const { payment } = await payOnce(stack, INPUT, "idem_verify_0001");
    const verdict = await stack.client.verifyIntentSettlement(payment.intentId);
    expect(verdict.status).toBe("final");
    expect(verdict.facts?.txHash).toBe(payment.settlement.txHash);
    expect(await tokenBalance(stack.chain, stack.token, stack.payeeAddress)).toBe(1500n);
  });

  it("reports no settlement for an intent it has never seen", async () => {
    const stack = await start();
    expect((await stack.client.verifyIntentSettlement("int_unknown")).status).toBe("no-settlement-recorded");
  });
});

describe("audit evidence", () => {
  it("records the whole lifecycle across the linked logs, with no raw signatures", async () => {
    const stack = await start();
    const { payment } = await payOnce(stack, INPUT, "idem_audit_0001");

    const { AuditLog, DurableStore, verifyLinkedAuditLogs } = await import("@pulseagent/core");
    const platformEvents = stack.client.readAudit();
    const signerStore = DurableStore.open(stack.signerDatabasePath);
    let signerEvents;
    try {
      signerEvents = new AuditLog(signerStore).read();
    } finally {
      signerStore.close();
    }

    const linkage = verifyLinkedAuditLogs(
      [
        { label: "platform", events: platformEvents, expectedTerminalHash: stack.client.auditTerminalHash },
        { label: "signer", events: signerEvents },
      ],
      {
        intentIds: [payment.intentId, payment.correlationId],
        requiredKinds: [
          "intent.created",
          "signer.reservation.held",
          "signer.authorization.signed",
          "payment.authorized",
          "payment.submitted",
          "settlement.verified",
          "result.delivered",
          "result.verified",
        ],
        expectedTerminalState: "DELIVERED",
      },
    );
    expect(linkage.findings.filter((finding) => finding.severity === "error")).toEqual([]);
    expect(linkage.ok).toBe(true);

    const serialized = JSON.stringify([...platformEvents, ...signerEvents]);
    expect(serialized).not.toMatch(/0x[0-9a-fA-F]{130,}/);
    expect(serialized).not.toMatch(/privateKey|mnemonic|Bearer /i);
  });

  it("detects a tampered exported log against its recorded terminal hash", async () => {
    const stack = await start();
    await payOnce(stack, INPUT, "idem_export_0001");
    const exported = await stack.client.exportAudit(path.join(stack.runtimeDir, "audit.jsonl"));

    const { readEventsFile, verifyAuditEvents } = await import("@pulseagent/core");
    const events = await readEventsFile(exported.filePath);
    expect(verifyAuditEvents(events, { expectedTerminalHash: exported.terminalHash }).ok).toBe(true);
    // A removed tail is only detectable against the recorded head.
    const truncated = verifyAuditEvents(events.slice(0, -1), { expectedTerminalHash: exported.terminalHash });
    expect(truncated.ok).toBe(false);
    expect(truncated.findings.map((finding) => finding.code)).toContain("terminal_hash_mismatch");
  });
});

/**
 * A fetch hook installed on the global binding for the duration of `work`.
 *
 * Used to inject real failures *after* the seller has done its work, which is
 * what a lost response actually is: the payment settled and the buyer never
 * found out. Deleting a cache entry after a successful delivery does not
 * reproduce that at all.
 */
async function withFetchHook<T>(
  hook: (url: string, response: Response | undefined) => Response | undefined | never,
  work: () => Promise<T>,
): Promise<T> {
  const original = globalThis.fetch;
  // Typed from the global `fetch` itself: `RequestInfo` is a DOM type and this
  // project does not include the DOM lib.
  type FetchInput = Parameters<typeof globalThis.fetch>[0];
  type FetchInit = Parameters<typeof globalThis.fetch>[1];
  globalThis.fetch = (async (input: FetchInput, init?: FetchInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const early = hook(url, undefined);
    if (early) return early;
    const response = await original(input, init);
    const replaced = hook(url, response);
    return replaced ?? response;
  }) as typeof globalThis.fetch;
  try {
    return await work();
  } finally {
    globalThis.fetch = original;
  }
}

describe("crash and ambiguity recovery", () => {
  it("keeps a pending identity when the paid response is lost, then recovers", async () => {
    const stack = await start();
    const { quote, service } = await stack.client.requestQuote({ serviceOrigin: stack.sellerOrigin, input: INPUT });
    const pay = (): Promise<unknown> =>
      stack.client.requestPayment({ quote, input: INPUT, idempotencyKey: "idem_loss_0001", serviceName: service.name });

    // The seller really settles and really answers; the buyer never sees it, and
    // its receipt endpoint is down too, so nothing can be recovered yet.
    await expect(
      withFetchHook((url, response) => {
        if (url.endsWith("/receipt")) return new Response("{}", { status: 503 });
        // Only the paid attempt. The first request to /digest is the unpaid one
        // that earns the 402 challenge; interfering with it would prevent the
        // payment instead of losing its response.
        if (url.endsWith("/digest") && response?.status === 200) throw new TypeError("fetch failed");
        return undefined;
      }, pay),
    ).rejects.toThrow();

    // One payment happened on chain, and the buyer holds its identity.
    expect(await tokenBalance(stack.chain, stack.token, stack.payeeAddress)).toBe(1500n);
    const pending = stack.client.getIntentStatus(
      stack.client.readAudit().find((event) => event.kind === "payment.authorized")?.intentId ?? "",
    );
    expect(pending?.authorizationNonce).toMatch(/^0x[0-9a-f]{64}$/i);
    expect(["AUTHORIZED", "SUBMITTED", "RECONCILING"]).toContain(pending?.state);

    // While the receipt endpoint is still down, a retry must stay pending and
    // must not issue a second authorization.
    const noncesBefore = countAuthorizations(stack);
    await expect(
      withFetchHook((url) => (url.endsWith("/receipt") ? new Response("{}", { status: 503 }) : undefined), pay),
    ).rejects.toThrow(/already holds an authorization|could not be recovered/);
    expect(countAuthorizations(stack)).toBe(noncesBefore);
    expect(await tokenBalance(stack.chain, stack.token, stack.payeeAddress)).toBe(1500n);

    // With the seller reachable again, the same retry collects what was paid for.
    const recovered = (await pay()) as { settlement: { txHash: string }; result: { sha256: string } };
    expect(recovered.result.sha256).toBe(sha256(INPUT));
    expect(await tokenBalance(stack.chain, stack.token, stack.payeeAddress)).toBe(1500n);
    expect(countAuthorizations(stack)).toBe(noncesBefore);
  });

  it("saves the known transaction hash when the seller reports 202, and stays reconcilable", async () => {
    const stack = await start();
    const { quote, service } = await stack.client.requestQuote({ serviceOrigin: stack.sellerOrigin, input: INPUT });
    const pay = (): Promise<unknown> =>
      stack.client.requestPayment({ quote, input: INPUT, idempotencyKey: "idem_202_0001", serviceName: service.name });

    // The settlement is real; the buyer is told it is not yet final.
    await expect(
      withFetchHook((url, response) => {
        if (!url.endsWith("/digest") || response?.status !== 200) return undefined;
        return rewriteAsStatus(response, 202, "pending-finality");
      }, pay),
    ).rejects.toThrow(/not yet final/);

    const intentId = stack.client.readAudit().find((event) => event.kind === "payment.pending")?.intentId ?? "";
    const intent = stack.client.getIntentStatus(intentId);
    expect(intent?.state).toBe("RECONCILING");
    // The hash must be saved before finality, or a settlement that later
    // finalizes has no local identity to reconcile against.
    expect(intent?.settlementTxHash).toMatch(/^0x[0-9a-f]{64}$/i);

    const recovered = (await pay()) as { settlement: { txHash: string } };
    expect(recovered.settlement.txHash).toBe(intent?.settlementTxHash);
    expect(await tokenBalance(stack.chain, stack.token, stack.payeeAddress)).toBe(1500n);
  });

  it("treats a 5xx after a possible submission as reconcilable, never as denied", async () => {
    const stack = await start();
    const { quote, service } = await stack.client.requestQuote({ serviceOrigin: stack.sellerOrigin, input: INPUT });
    const pay = (): Promise<unknown> =>
      stack.client.requestPayment({ quote, input: INPUT, idempotencyKey: "idem_5xx_0001", serviceName: service.name });

    await expect(
      withFetchHook((url, response) => {
        if (url.endsWith("/receipt")) return new Response("{}", { status: 503 });
        if (!url.endsWith("/digest") || response?.status !== 200) return undefined;
        return rewriteAsStatus(response, 503, "server_error");
      }, pay),
    ).rejects.toThrow();

    const authorized = stack.client.readAudit().find((event) => event.kind === "payment.authorized");
    const intent = stack.client.getIntentStatus(authorized?.intentId ?? "");
    // DENIED is terminal and would invite a fresh authorization for a payment
    // that may already have settled.
    expect(intent?.state).not.toBe("DENIED");
    expect(["RECONCILING", "SUBMITTED", "AUTHORIZED"]).toContain(intent?.state);

    const recovered = (await pay()) as { result: { sha256: string } };
    expect(recovered.result.sha256).toBe(sha256(INPUT));
    expect(await tokenBalance(stack.chain, stack.token, stack.payeeAddress)).toBe(1500n);
  });

  it("survives a seller and buyer restart with the chain and signer still running", async () => {
    const stack = await start();
    const { quote, service, payment } = await payOnce(stack, INPUT, "idem_restart_0001");

    // Services restart; the chain and the key-holding signer stay up. Any
    // settlement record kept only in memory is gone at this point.
    await stack.restartSeller();
    const buyer = await stack.restartBuyer();

    const afterRestart = await buyer.requestPayment({
      quote,
      input: INPUT,
      idempotencyKey: "idem_restart_0001",
      serviceName: service.name,
    });
    expect(afterRestart.settlement.txHash).toBe(payment.settlement.txHash);
    expect(afterRestart.result.sha256).toBe(sha256(INPUT));
    expect(await tokenBalance(stack.chain, stack.token, stack.payeeAddress)).toBe(1500n);

    // A different payment still works after the restart.
    const other = "a different input after restart";
    const second = await payOnce(stack, other, "idem_restart_0002");
    expect(second.payment.result.sha256).toBe(sha256(other));
    expect(await tokenBalance(stack.chain, stack.token, stack.payeeAddress)).toBe(3000n);
  });

  it("survives a facilitator restart without reusing a nonce or paying twice", async () => {
    const stack = await start();
    const first = await payOnce(stack, INPUT, "idem_facrestart_0001");

    // The gas account is regenerated, but the broadcast claims and the sender
    // nonce counter are durable and must carry over.
    await stack.restartFacilitator();

    // The already-paid intent still recovers, with no second settlement.
    const recovered = await stack.client.requestPayment({
      quote: first.quote,
      input: INPUT,
      idempotencyKey: "idem_facrestart_0001",
      serviceName: first.service.name,
    });
    expect(recovered.settlement.txHash).toBe(first.payment.settlement.txHash);
    expect(await tokenBalance(stack.chain, stack.token, stack.payeeAddress)).toBe(1500n);

    // And a new payment settles through the restarted facilitator.
    const other = "a purchase after the facilitator restarted";
    const second = await payOnce(stack, other, "idem_facrestart_0002");
    expect(second.payment.result.sha256).toBe(sha256(other));
    expect(second.payment.settlement.txHash).not.toBe(first.payment.settlement.txHash);
    expect(await tokenBalance(stack.chain, stack.token, stack.payeeAddress)).toBe(3000n);
  });

  it("settles a distinct payment after a race on a first payment", async () => {
    // The racing duplicates must not leave the facilitator's nonce sequence with
    // a gap, which would stop every later transaction from that account.
    const stack = await start();
    const { quote, service } = await stack.client.requestQuote({ serviceOrigin: stack.sellerOrigin, input: INPUT });
    const outcomes = await Promise.allSettled([
      stack.client.requestPayment({ quote, input: INPUT, idempotencyKey: "idem_race2_0001", serviceName: service.name }),
      stack.client.requestPayment({ quote, input: INPUT, idempotencyKey: "idem_race2_0001", serviceName: service.name }),
      stack.client.requestPayment({ quote, input: INPUT, idempotencyKey: "idem_race2_0001", serviceName: service.name }),
    ]);
    expect(outcomes.every((outcome) => outcome.status === "fulfilled")).toBe(true);
    expect(await tokenBalance(stack.chain, stack.token, stack.payeeAddress)).toBe(1500n);

    const other = "an entirely different purchase";
    const second = await payOnce(stack, other, "idem_race2_0002");
    expect(second.payment.result.sha256).toBe(sha256(other));
    expect(second.payment.settlement.txHash).not.toBe(
      (outcomes[0] as PromiseFulfilledResult<{ settlement: { txHash: string } }>).value.settlement.txHash,
    );
    expect(await tokenBalance(stack.chain, stack.token, stack.payeeAddress)).toBe(3000n);
  });
});

/** Replays a real response body under a different status, keeping its facts. */
function rewriteAsStatus(response: Response, status: number, errorCode: string): Response {
  const clone = response.clone();
  return new Response(
    new ReadableStream({
      async start(controller) {
        const body = (await clone.json()) as { receipt?: { transactionHash?: string } };
        controller.enqueue(
          new TextEncoder().encode(
            JSON.stringify({
              error: "settlement_not_verified",
              status: errorCode,
              transactionHash: body.receipt?.transactionHash,
            }),
          ),
        );
        controller.close();
      },
    }),
    { status, headers: { "content-type": "application/json" } },
  );
}

/** How many distinct authorization nonces this buyer has ever been issued. */
function countAuthorizations(stack: LocalStack): number {
  return new Set(
    stack.client
      .readAudit()
      .filter((event) => event.kind === "payment.authorized")
      .map((event) => String((event.payload as { authorizationNonce?: unknown }).authorizationNonce)),
  ).size;
}
