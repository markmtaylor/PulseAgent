import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AuditLog, DurableStore, digestOf, verifyAuditEvents, type PaymentIntent } from "@pulseagent/core";

const open: DurableStore[] = [];
function store(dbPath: string): DurableStore {
  const instance = DurableStore.open(dbPath);
  open.push(instance);
  return instance;
}
function tempDb(): string {
  return path.join(mkdtempSync(path.join(tmpdir(), "pa-store-")), "state.sqlite");
}

afterEach(() => {
  while (open.length > 0) open.pop()?.close();
});

const LEGS = [{ asset: "0xAAaa", amountAtomic: "100", maxAmountPerPayment: "100", totalBudget: "250" }];

function reservation(overrides: Partial<Parameters<DurableStore["reserveBudget"]>[0]> = {}) {
  return {
    principalId: "buyer-a",
    policyRevision: "rev-1",
    intentId: "int_one",
    idempotencyKey: "idem_one",
    reservationId: "rsv_one",
    legs: LEGS,
    ...overrides,
  };
}

describe("durable budget reservations", () => {
  it("commits the amount atomically and reports the running total", () => {
    const db = tempDb();
    const s = store(db);
    const first = s.reserveBudget(reservation());
    expect(first.ok).toBe(true);
    expect(s.readCommittedSpend({ principalId: "buyer-a", policyRevision: "rev-1", asset: "0xaaaa" })).toBe(100n);
  });

  it("enforces the total budget across two independent handles on one database", () => {
    // The defect this replaces: each handle read the same stale total and both
    // found room, so a policy allowing one payment authorized two.
    const db = tempDb();
    const a = store(db);
    const b = store(db);
    expect(a.reserveBudget(reservation({ intentId: "int_a", idempotencyKey: "idem_a", reservationId: "rsv_a" })).ok).toBe(true);
    expect(b.reserveBudget(reservation({ intentId: "int_b", idempotencyKey: "idem_b", reservationId: "rsv_b" })).ok).toBe(true);
    const third = b.reserveBudget(reservation({ intentId: "int_c", idempotencyKey: "idem_c", reservationId: "rsv_c" }));
    expect(third.ok).toBe(false);
    if (!third.ok) expect(third.code).toBe("budget_exhausted");
    expect(a.readCommittedSpend({ principalId: "buyer-a", policyRevision: "rev-1", asset: "0xaaaa" })).toBe(200n);
  });

  it("survives a reopen, so a restart cannot reset the budget", () => {
    const db = tempDb();
    const first = store(db);
    first.reserveBudget(reservation());
    first.close();
    open.pop();
    const reopened = store(db);
    expect(reopened.readCommittedSpend({ principalId: "buyer-a", policyRevision: "rev-1", asset: "0xaaaa" })).toBe(100n);
    const again = reopened.reserveBudget(reservation({ intentId: "int_z", idempotencyKey: "idem_z", reservationId: "rsv_z" }));
    expect(again.ok).toBe(true);
    const third = reopened.reserveBudget(reservation({ intentId: "int_y", idempotencyKey: "idem_y", reservationId: "rsv_y" }));
    expect(third.ok).toBe(false);
  });

  it("returns the original reservation for an identical retry", () => {
    const s = store(tempDb());
    const first = s.reserveBudget(reservation());
    const retry = s.reserveBudget(reservation());
    expect(retry.ok).toBe(true);
    if (first.ok && retry.ok) {
      expect(retry.replayed).toBe(true);
      expect(retry.reservationId).toBe(first.reservationId);
    }
    // The retry must not have committed a second time.
    expect(s.readCommittedSpend({ principalId: "buyer-a", policyRevision: "rev-1", asset: "0xaaaa" })).toBe(100n);
  });

  it("refuses a retry that changes any immutable term", () => {
    // Executed review finding: a retry asking for 900 under the same ids was
    // handed the original 100-unit reservation and reported success.
    const s = store(tempDb());
    expect(s.reserveBudget(reservation()).ok).toBe(true);

    for (const [name, changed] of [
      ["amount", reservation({ legs: [{ ...LEGS[0]!, amountAtomic: "900", maxAmountPerPayment: "900" }] })],
      ["principal", reservation({ principalId: "buyer-b" })],
      ["policy revision", reservation({ policyRevision: "rev-2" })],
      ["asset", reservation({ legs: [{ ...LEGS[0]!, asset: "0xBBbb" }] })],
      ["limits", reservation({ legs: [{ ...LEGS[0]!, totalBudget: "999999" }] })],
    ] as const) {
      const result = s.reserveBudget(changed);
      expect(result.ok, `changing the ${name} must be refused`).toBe(false);
      if (!result.ok) expect(result.code).toBe("reservation_binding_changed");
    }
    expect(s.readCommittedSpend({ principalId: "buyer-a", policyRevision: "rev-1", asset: "0xaaaa" })).toBe(100n);
  });

  it("refuses an idempotency key already bound to another intent", () => {
    const s = store(tempDb());
    expect(s.reserveBudget(reservation()).ok).toBe(true);
    const stolen = s.reserveBudget(reservation({ intentId: "int_other", reservationId: "rsv_other" }));
    expect(stolen.ok).toBe(false);
    if (!stolen.ok) expect(stolen.code).toBe("idempotency_key_bound_to_other_intent");
  });

  it("commits every leg or none", () => {
    const s = store(tempDb());
    const result = s.reserveBudget(
      reservation({
        legs: [
          LEGS[0]!,
          { asset: "native:gas", amountAtomic: "5000", maxAmountPerPayment: "5000", totalBudget: "100" },
        ],
      }),
    );
    expect(result.ok).toBe(false);
    // The token leg must not have been committed by the leg that fit.
    expect(s.readCommittedSpend({ principalId: "buyer-a", policyRevision: "rev-1", asset: "0xaaaa" })).toBe(0n);
  });
});

describe("authorization binding", () => {
  const bind = (overrides: Partial<Parameters<DurableStore["bindAuthorization"]>[0]> = {}) => ({
    ...reservation(),
    authorizationDigest: digestOf({ nonce: 1 }),
    payer: "0xCCcc000000000000000000000000000000000000",
    authorizationNonce: `0x${"01".repeat(32)}`,
    ...overrides,
  });

  it("binds an intent to exactly one authorization", () => {
    const s = store(tempDb());
    expect(s.bindAuthorization(bind()).ok).toBe(true);
    const exact = s.bindAuthorization(bind());
    expect(exact.ok).toBe(true);
    if (exact.ok) expect(exact.replayed).toBe(true);
  });

  it("refuses a second authorization for the same intent", () => {
    // Executed review finding: three requests differing only in nonce produced
    // three spendable signatures against one reservation.
    const s = store(tempDb());
    expect(s.bindAuthorization(bind()).ok).toBe(true);
    const changedNonce = s.bindAuthorization({
      ...bind(),
      authorizationDigest: digestOf({ nonce: 2 }),
      authorizationNonce: `0x${"02".repeat(32)}`,
    });
    expect(changedNonce.ok).toBe(false);
    if (!changedNonce.ok) expect(changedNonce.code).toBe("authorization_already_bound");
  });

  it("refuses reusing one nonce under a different intent", () => {
    const s = store(tempDb());
    expect(s.bindAuthorization(bind()).ok).toBe(true);
    const reused = s.bindAuthorization({
      ...bind(),
      intentId: "int_two",
      idempotencyKey: "idem_two",
      reservationId: "rsv_two",
      authorizationDigest: digestOf({ nonce: 3 }),
    });
    expect(reused.ok).toBe(false);
    if (!reused.ok) expect(reused.code).toBe("nonce_bound_to_other_intent");
  });

  it("rolls back every claim when a bind is refused", () => {
    // A refusal that committed its claims would leave the intent bound to an
    // authorization that was never issued, blocking the legitimate retry.
    const s = store(tempDb());
    const refused = s.bindAuthorization({
      ...bind(),
      legs: [{ asset: "0xAAaa", amountAtomic: "500", maxAmountPerPayment: "100", totalBudget: "250" }],
    });
    expect(refused.ok).toBe(false);
    expect(s.readClaim("authorization", "int_one")).toBeUndefined();
    expect(s.readClaim("auth-nonce", `0xcccc000000000000000000000000000000000000:0x${"01".repeat(32)}`)).toBeUndefined();
    // The legitimate attempt then succeeds.
    expect(s.bindAuthorization(bind()).ok).toBe(true);
  });
});

describe("sender nonce allocation", () => {
  it("never reuses a nonce after a lost broadcast response", () => {
    // The node's pending count stays put when a signed transaction never
    // reaches it. Allocating from that alone displaces the earlier transaction.
    const s = store(tempDb());
    expect(s.allocateSenderNonce("eip155:31337:0xabc", 0)).toBe(0);
    expect(s.allocateSenderNonce("eip155:31337:0xabc", 0)).toBe(1);
    expect(s.allocateSenderNonce("eip155:31337:0xabc", 0)).toBe(2);
    // It still follows the chain forward when the node is ahead of us.
    expect(s.allocateSenderNonce("eip155:31337:0xabc", 10)).toBe(10);
    expect(s.allocateSenderNonce("eip155:31337:0xabc", 0)).toBe(11);
    // Separate senders keep separate counters.
    expect(s.allocateSenderNonce("eip155:31337:0xdef", 0)).toBe(0);
  });

  it("keeps the counter across a reopen", () => {
    const db = tempDb();
    const first = store(db);
    expect(first.allocateSenderNonce("k", 0)).toBe(0);
    first.close();
    open.pop();
    expect(store(db).allocateSenderNonce("k", 0)).toBe(1);
  });
});

describe("single-use claims", () => {
  it("lets exactly one caller claim a key, across handles", () => {
    const db = tempDb();
    const a = store(db);
    const b = store(db);
    expect(a.claimOnce("quote", "q1", "owner-a")).toEqual({ claimed: true });
    expect(b.claimOnce("quote", "q1", "owner-b")).toEqual({ claimed: false, existing: "owner-a" });
    expect(b.readClaim("quote", "q1")).toBe("owner-a");
  });

  it("treats distinct opaque ids as distinct, with no normalization", () => {
    // Two ids that an earlier path-based store collapsed onto one record.
    const s = store(tempDb());
    expect(s.claimOnce("intent", "intent:123", "a")).toEqual({ claimed: true });
    expect(s.claimOnce("intent", "intent_123", "b")).toEqual({ claimed: true });
    expect(s.readClaim("intent", "intent:123")).toBe("a");
    expect(s.readClaim("intent", "intent_123")).toBe("b");
  });
});

describe("intent records", () => {
  const intent: PaymentIntent = {
    intentId: "int_record_one",
    idempotencyKey: "idem_record_one",
    principalId: "buyer-a",
    policyRevision: "rev-1",
    createdAt: 1_800_000_000,
    state: "POLICY_APPROVED",
    quote: {
      quoteId: "quote_abcdef123456",
      serviceOrigin: "http://127.0.0.1:8080",
      resourcePath: "/digest",
      requestDigest: `sha256:${"a".repeat(64)}`,
      network: "eip155:31337",
      asset: "0x1111111111111111111111111111111111111111",
      assetDecimals: 6,
      payTo: "0x2222222222222222222222222222222222222222",
      amount: "1500",
      expiresAt: 1_800_000_120,
      eip712Name: "Test Token",
      eip712Version: "1",
      assetTransferMethod: "eip3009",
      maxTimeoutSeconds: 120,
    },
  };

  it("stores, reads back and updates an intent in one transaction", () => {
    const s = store(tempDb());
    s.putIntent(intent);
    expect(s.getIntent(intent.intentId)?.state).toBe("POLICY_APPROVED");
    const updated = s.updateIntent(intent.intentId, (current) => ({ ...current, state: "AUTHORIZED" }));
    expect(updated.state).toBe("AUTHORIZED");
    expect(s.listIntentsInState("AUTHORIZED").map((i) => i.intentId)).toEqual([intent.intentId]);
  });

  it("refuses a mutation that changes the intent id", () => {
    const s = store(tempDb());
    s.putIntent(intent);
    expect(() => s.updateIntent(intent.intentId, (current) => ({ ...current, intentId: "int_other" }))).toThrow(
      /must not change the intent id/,
    );
  });

  it("validates a record on the way in", () => {
    const s = store(tempDb());
    // A fractional amount must not be storable at all.
    expect(() => s.putIntent({ ...intent, quote: { ...intent.quote, amount: "1.5" } })).toThrow();
  });
});

describe("audit sequence allocation", () => {
  it("gives concurrent appends distinct sequence numbers and a single chain", async () => {
    // The defect this replaces: seq and prevHash were read before the first
    // await, so two concurrent appends produced records with the same sequence
    // number and the same parent.
    const db = tempDb();
    const log = new AuditLog(store(db));
    await Promise.all(
      Array.from({ length: 12 }, (_, index) =>
        Promise.resolve().then(() =>
          log.append({ actor: "buyer", kind: "test.event", payload: { index } }),
        ),
      ),
    );
    const events = log.read();
    expect(events).toHaveLength(12);
    expect(events.map((event) => event.seq)).toEqual([...Array(12).keys()].map((index) => index + 1));
    expect(verifyAuditEvents(events).ok).toBe(true);
  });

  it("keeps one chain across two handles on the same database", () => {
    const db = tempDb();
    const first = new AuditLog(store(db));
    const second = new AuditLog(store(db));
    first.append({ actor: "buyer", kind: "a", payload: {} });
    second.append({ actor: "signer", kind: "b", payload: {} });
    first.append({ actor: "seller", kind: "c", payload: {} });
    const events = first.read();
    expect(events.map((event) => event.seq)).toEqual([1, 2, 3]);
    expect(verifyAuditEvents(events).ok).toBe(true);
  });

  it("resumes the chain after a reopen", () => {
    const db = tempDb();
    const first = new AuditLog(store(db));
    first.append({ actor: "buyer", kind: "a", payload: {} });
    const head = first.terminalHash;
    open[open.length - 1]?.close();
    open.pop();
    const reopened = new AuditLog(store(db));
    const next = reopened.append({ actor: "buyer", kind: "b", payload: {} });
    expect(next.seq).toBe(2);
    expect(next.prevHash).toBe(head);
    expect(verifyAuditEvents(reopened.read()).ok).toBe(true);
  });
});
