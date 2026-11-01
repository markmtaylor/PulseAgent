import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  AUDIT_GENESIS_HASH,
  AuditLog,
  DurableStore,
  digestOf,
  verifyAuditEvents,
  verifyLinkedAuditLogs,
  type AuditEvent,
} from "@pulseagent/core";

const open: DurableStore[] = [];
function freshLog(): AuditLog {
  const dir = mkdtempSync(path.join(tmpdir(), "pa-audit-"));
  const store = DurableStore.open(path.join(dir, "state.sqlite"));
  open.push(store);
  return new AuditLog(store);
}
afterEach(() => {
  while (open.length > 0) open.pop()?.close();
});

/** Rebuilds the chain so hashes are valid, which is how a forged log would look. */
function rehash(events: readonly Omit<AuditEvent, "eventHash" | "prevHash" | "seq">[]): AuditEvent[] {
  let prevHash = AUDIT_GENESIS_HASH;
  return events.map((event, index) => {
    const unhashed = { ...event, seq: index + 1, prevHash };
    const eventHash = digestOf(unhashed);
    prevHash = eventHash;
    return { ...unhashed, eventHash } as AuditEvent;
  });
}

const base = { schemaVersion: 1 as const, at: "2026-11-01T00:00:00Z", policyRevision: "rev-1" };

function lifecycle(): AuditEvent[] {
  return rehash([
    { ...base, actor: "buyer", kind: "intent.created", intentId: "int_1", state: "POLICY_APPROVED", payload: {} },
    { ...base, actor: "buyer", kind: "payment.authorized", intentId: "int_1", state: "AUTHORIZED", payload: {} },
    { ...base, actor: "buyer", kind: "payment.submitted", intentId: "int_1", state: "SUBMITTED", payload: {} },
    { ...base, actor: "verifier", kind: "settlement.verified", intentId: "int_1", state: "FINALIZED", payload: {} },
    { ...base, actor: "seller", kind: "result.delivered", intentId: "int_1", state: "DELIVERED", payload: {} },
  ]);
}

describe("audit chain integrity", () => {
  it("accepts a well-formed log it wrote itself", () => {
    const log = freshLog();
    log.append({ actor: "buyer", kind: "a", payload: { x: "1" } });
    log.append({ actor: "buyer", kind: "b", payload: { x: "2" } });
    const report = verifyAuditEvents(log.read(), { expectedTerminalHash: log.terminalHash });
    expect(report.ok).toBe(true);
    expect(report.locallyRewritable).toBe(true);
  });

  it("detects an edited interior record", () => {
    const log = freshLog();
    log.append({ actor: "buyer", kind: "a", payload: { x: "1" } });
    log.append({ actor: "buyer", kind: "b", payload: { x: "2" } });
    const events = log.read();
    const tampered = [...events];
    tampered[0] = { ...events[0]!, payload: { x: "changed" } };
    const report = verifyAuditEvents(tampered);
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.code)).toContain("event_hash_mismatch");
  });

  it("detects a removed interior record", () => {
    const log = freshLog();
    for (const kind of ["a", "b", "c"]) log.append({ actor: "buyer", kind, payload: {} });
    const events = log.read();
    const report = verifyAuditEvents([events[0]!, events[2]!]);
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.code)).toEqual(expect.arrayContaining(["sequence_gap", "chain_break"]));
  });

  it("detects a truncated tail only when a terminal hash is pinned elsewhere", () => {
    const log = freshLog();
    for (const kind of ["a", "b", "c"]) log.append({ actor: "buyer", kind, payload: {} });
    const pinned = log.terminalHash;
    const truncated = log.read().slice(0, 2);

    // Without the external anchor, a truncated log is internally consistent.
    const blind = verifyAuditEvents(truncated);
    expect(blind.ok).toBe(true);
    expect(blind.findings.map((f) => f.code)).toContain("no_external_anchor");

    const anchored = verifyAuditEvents(truncated, { expectedTerminalHash: pinned });
    expect(anchored.ok).toBe(false);
    expect(anchored.findings.map((f) => f.code)).toContain("terminal_hash_mismatch");
  });

  it("always reports that the log is locally rewritable", () => {
    // A rebuilt chain is internally valid, which is exactly the limit of this check.
    const forged = verifyAuditEvents(lifecycle(), { requireCompleteLifecycle: true });
    expect(forged.ok).toBe(true);
    expect(forged.locallyRewritable).toBe(true);
  });
});

describe("audit lifecycle semantics", () => {
  it("accepts a correctly ordered lifecycle", () => {
    expect(verifyAuditEvents(lifecycle(), { requireCompleteLifecycle: true }).ok).toBe(true);
  });

  it("rejects a delivery recorded before its settlement, even with valid hashes", () => {
    // Hash integrity says the records were not edited. It says nothing about
    // whether the sequence they describe could have happened.
    const events = rehash([
      { ...base, actor: "buyer", kind: "intent.created", intentId: "int_1", state: "POLICY_APPROVED", payload: {} },
      { ...base, actor: "buyer", kind: "payment.authorized", intentId: "int_1", state: "AUTHORIZED", payload: {} },
      { ...base, actor: "seller", kind: "result.delivered", intentId: "int_1", state: "FINALIZED", payload: {} },
      { ...base, actor: "verifier", kind: "settlement.verified", intentId: "int_1", state: "DELIVERED", payload: {} },
    ]);
    const report = verifyAuditEvents(events, { requireCompleteLifecycle: true });
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.code)).toContain("delivery_before_settlement");
  });

  it("rejects a record that continues an intent after a terminal state", () => {
    const events = rehash([
      ...lifecycle().map(({ eventHash: _h, prevHash: _p, seq: _s, ...rest }) => rest),
      { ...base, actor: "buyer", kind: "payment.submitted", intentId: "int_1", state: "SUBMITTED", payload: {} },
    ]);
    const report = verifyAuditEvents(events, { requireCompleteLifecycle: true });
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.code)).toContain("record_after_terminal_state");
  });

  it("rejects an impossible state transition", () => {
    const events = rehash([
      { ...base, actor: "buyer", kind: "intent.created", intentId: "int_1", state: "POLICY_APPROVED", payload: {} },
      { ...base, actor: "seller", kind: "result.delivered", intentId: "int_1", state: "DELIVERED", payload: {} },
    ]);
    const report = verifyAuditEvents(events, { requireCompleteLifecycle: true });
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.code)).toContain("illegal_state_transition");
  });

  it("rejects a delivered intent with no settlement recorded before it", () => {
    const events = rehash([
      { ...base, actor: "buyer", kind: "intent.created", intentId: "int_1", state: "POLICY_APPROVED", payload: {} },
      { ...base, actor: "buyer", kind: "payment.authorized", intentId: "int_1", state: "AUTHORIZED", payload: {} },
      { ...base, actor: "buyer", kind: "x", intentId: "int_1", state: "FINALIZED", payload: {} },
      { ...base, actor: "seller", kind: "result.delivered", intentId: "int_1", state: "DELIVERED", payload: {} },
    ]);
    const report = verifyAuditEvents(events, { requireCompleteLifecycle: true });
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.code)).toContain("delivery_without_settlement");
  });

  it("rejects a state change on a record that names no intent", () => {
    const events = rehash([{ ...base, actor: "buyer", kind: "x", state: "DELIVERED", payload: {} }]);
    const report = verifyAuditEvents(events);
    expect(report.findings.map((f) => f.code)).toContain("state_without_intent");
  });

  it("requires a policy revision on every intent's records", () => {
    const events = rehash([
      { actor: "buyer", kind: "intent.created", intentId: "int_1", state: "POLICY_APPROVED", payload: {}, schemaVersion: 1, at: "2026-11-01T00:00:00Z" },
      { actor: "seller", kind: "result.delivered", intentId: "int_1", state: "DENIED", payload: {}, schemaVersion: 1, at: "2026-11-01T00:00:00Z" },
    ]);
    const report = verifyAuditEvents(events, { requireCompleteLifecycle: true });
    expect(report.findings.map((f) => f.code)).toContain("missing_policy_linkage");
  });

  it("does not demand a complete lifecycle from a partial per-process log", () => {
    // The signer's log legitimately ends at AUTHORIZED.
    const partial = rehash([
      { ...base, actor: "signer", kind: "signer.reservation.held", intentId: "int_1", state: "RESERVED", payload: {} },
      { ...base, actor: "signer", kind: "signer.authorization.signed", intentId: "int_1", state: "AUTHORIZED", payload: {} },
    ]);
    expect(verifyAuditEvents(partial).ok).toBe(true);
    // And says so when completeness is demanded of it.
    expect(verifyAuditEvents(partial, { requireCompleteLifecycle: true }).ok).toBe(false);
  });
});

describe("linked logs", () => {
  // Payloads carry the immutable facts real records do. Empty payloads would
  // only ever prove that records of the right kind exist.
  const QUOTE_A = "quote_aaaaaaaaaa";
  const NONCE_A = `0x${"a1".repeat(32)}`;
  const PAYER = "0x1111111111111111111111111111111111111111";
  const ASSET = "0x5555555555555555555555555555555555555555";
  const PAYEE = "0x6666666666666666666666666666666666666666";
  const TX = `0x${"d1".repeat(32)}`;
  const SIG_DIGEST = `sha256:${"e".repeat(64)}`;
  const AUTH_DIGEST = `sha256:${"f".repeat(64)}`;
  const RESULT_DIGEST = `sha256:${"9".repeat(64)}`;
  // The facts each stage must carry so the next stage links to it.
  const facts = {
    quoteId: QUOTE_A,
    authorizationNonce: NONCE_A,
    payer: PAYER,
    amountAtomic: "1500",
    asset: ASSET,
    payTo: PAYEE,
  };

  const signerLog = rehash([
    { ...base, actor: "signer", kind: "signer.reservation.held", intentId: "int_1", state: "RESERVED", payload: { ...facts, authorizationDigest: AUTH_DIGEST } },
    {
      ...base,
      actor: "signer",
      kind: "signer.authorization.signed",
      intentId: "int_1",
      state: "AUTHORIZED",
      payload: { ...facts, signatureDigest: SIG_DIGEST, authorizationDigest: AUTH_DIGEST },
    },
  ]);
  const platformLog = rehash([
    { ...base, actor: "buyer", kind: "intent.created", intentId: "int_1", state: "POLICY_APPROVED", payload: { quoteId: QUOTE_A, amountAtomic: "1500" } },
    { ...base, actor: "buyer", kind: "payment.authorized", intentId: "int_1", state: "AUTHORIZED", payload: { ...facts } },
    { ...base, actor: "buyer", kind: "payment.submitted", intentId: "int_1", state: "SUBMITTED", payload: { ...facts } },
    // This record names both ids, which is what establishes the link.
    {
      ...base,
      actor: "buyer",
      kind: "settlement.verified",
      intentId: "int_1",
      state: "FINALIZED",
      payload: { ...facts, correlationId: "pay_1", transactionHash: TX },
    },
    {
      ...base,
      actor: "verifier",
      kind: "settlement.verified",
      intentId: "pay_1",
      state: "FINALIZED",
      payload: { ...facts, transactionHash: TX },
    },
    {
      ...base,
      actor: "seller",
      kind: "result.delivered",
      intentId: "pay_1",
      state: "DELIVERED",
      payload: { ...facts, transactionHash: TX, resultDigest: RESULT_DIGEST },
    },
  ]);
  const requiredKinds = [
    "intent.created",
    "signer.reservation.held",
    "signer.authorization.signed",
    "payment.submitted",
    "settlement.verified",
    "result.delivered",
  ];

  it("joins one payment recorded under two id spaces", () => {
    const report = verifyLinkedAuditLogs(
      [
        { label: "platform", events: platformLog },
        { label: "signer", events: signerLog },
      ],
      { intentIds: ["int_1", "pay_1"], requiredKinds, expectedTerminalState: "DELIVERED" },
    );
    expect(report.ok).toBe(true);
    expect(report.kinds.every((kind) => kind.label !== undefined)).toBe(true);
  });

  it("fails when a required record is absent from every log", () => {
    const report = verifyLinkedAuditLogs(
      [{ label: "platform", events: platformLog }],
      { intentIds: ["int_1", "pay_1"], requiredKinds, expectedTerminalState: "DELIVERED" },
    );
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.code)).toContain("missing_linked_record");
  });

  it("rejects two unrelated payments presented as one", () => {
    // Executed review finding: supplying both ids was enough to join a signer
    // record for one payment to a seller record for an entirely different one.
    const otherPayment = rehash([
      {
        ...base,
        actor: "verifier",
        kind: "settlement.verified",
        intentId: "pay_1",
        state: "FINALIZED",
        payload: { quoteId: "quote_bbbbbbbbbb", authorizationNonce: `0x${"b2".repeat(32)}`, amountAtomic: "999" },
      },
      {
        ...base,
        actor: "seller",
        kind: "result.delivered",
        intentId: "pay_1",
        state: "DELIVERED",
        payload: { quoteId: "quote_bbbbbbbbbb", amountAtomic: "999" },
      },
    ]);
    const report = verifyLinkedAuditLogs(
      [
        { label: "platform", events: otherPayment },
        { label: "signer", events: signerLog },
      ],
      { intentIds: ["int_1", "pay_1"], requiredKinds, expectedTerminalState: "DELIVERED" },
    );
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.code)).toContain("contradictory_linkage");
  });

  it("rejects a settlement that consumed a different authorization than the one signed", () => {
    const mismatched = rehash(
      platformLog.map(({ eventHash: _h, prevHash: _p, seq: _s, ...rest }) =>
        rest.kind === "settlement.verified" && rest.actor === "verifier"
          ? { ...rest, payload: { ...rest.payload, authorizationNonce: `0x${"99".repeat(32)}` } }
          : rest,
      ),
    );
    const report = verifyLinkedAuditLogs(
      [
        { label: "platform", events: mismatched },
        { label: "signer", events: signerLog },
      ],
      { intentIds: ["int_1", "pay_1"], requiredKinds, expectedTerminalState: "DELIVERED" },
    );
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.code)).toEqual(
      expect.arrayContaining(["contradictory_linkage"]),
    );
  });

  it("rejects a delivery citing a different settlement transaction", () => {
    const mismatched = rehash(
      platformLog.map(({ eventHash: _h, prevHash: _p, seq: _s, ...rest }) =>
        rest.kind === "result.delivered"
          ? { ...rest, payload: { ...rest.payload, transactionHash: `0x${"ee".repeat(32)}` } }
          : rest,
      ),
    );
    const report = verifyLinkedAuditLogs(
      [
        { label: "platform", events: mismatched },
        { label: "signer", events: signerLog },
      ],
      { intentIds: ["int_1", "pay_1"], requiredKinds, expectedTerminalState: "DELIVERED" },
    );
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.code)).toEqual(expect.arrayContaining(["contradictory_linkage"]));
  });

  it("rejects a stage record that omits the field linking it onward", () => {
    // A record of the right kind with the field missing proves only that
    // something was written.
    const stripped = rehash(
      signerLog.map(({ eventHash: _h, prevHash: _p, seq: _s, ...rest }) =>
        rest.kind === "signer.authorization.signed"
          ? {
              ...rest,
              payload: Object.fromEntries(
                Object.entries(rest.payload).filter(([key]) => key !== "signatureDigest"),
              ),
            }
          : rest,
      ),
    );
    const report = verifyLinkedAuditLogs(
      [
        { label: "platform", events: platformLog },
        { label: "signer", events: stripped },
      ],
      { intentIds: ["int_1", "pay_1"], requiredKinds, expectedTerminalState: "DELIVERED" },
    );
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.code)).toContain("incomplete_stage_record");
  });

  it("rejects one actor recording a payment under two policy revisions", () => {
    const switched = rehash(
      platformLog.map(({ eventHash: _h, prevHash: _p, seq: _s, ...rest }) =>
        rest.kind === "payment.submitted" ? { ...rest, policyRevision: "rev-2" } : rest,
      ),
    );
    const report = verifyLinkedAuditLogs(
      [
        { label: "platform", events: switched },
        { label: "signer", events: signerLog },
      ],
      { intentIds: ["int_1", "pay_1"], requiredKinds, expectedTerminalState: "DELIVERED" },
    );
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.message).join(" ")).toMatch(/more than one policy revision/);
  });

  it("accepts different actors acting under their own policy revisions", () => {
    // The buyer's spending policy and the seller's pricing configuration are
    // different documents; requiring one revision across both would conflate them.
    const sellerOwnRevision = rehash(
      platformLog.map(({ eventHash: _h, prevHash: _p, seq: _s, ...rest }) =>
        rest.actor === "seller" || rest.actor === "verifier" ? { ...rest, policyRevision: "seller-rev-1" } : rest,
      ),
    );
    const report = verifyLinkedAuditLogs(
      [
        { label: "platform", events: sellerOwnRevision },
        { label: "signer", events: signerLog },
      ],
      { intentIds: ["int_1", "pay_1"], requiredKinds, expectedTerminalState: "DELIVERED" },
    );
    expect(report.findings.filter((f) => f.severity === "error")).toEqual([]);
  });

  it("refuses to accept ids the records never tie together", () => {
    const untied = rehash(
      platformLog.map(({ eventHash: _h, prevHash: _p, seq: _s, ...rest }) => ({
        ...rest,
        payload: Object.fromEntries(Object.entries(rest.payload).filter(([key]) => key !== "correlationId")),
      })),
    );
    const report = verifyLinkedAuditLogs(
      [
        { label: "platform", events: untied },
        { label: "signer", events: signerLog },
      ],
      { intentIds: ["int_1", "pay_1"], requiredKinds, expectedTerminalState: "DELIVERED" },
    );
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.code)).toContain("linkage_not_established");
  });

  it("fails when the payment never reaches the expected terminal state", () => {
    const report = verifyLinkedAuditLogs(
      [
        { label: "platform", events: platformLog.slice(0, 3) },
        { label: "signer", events: signerLog },
      ],
      { intentIds: ["int_1", "pay_1"], requiredKinds, expectedTerminalState: "DELIVERED" },
    );
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.code)).toContain("linked_terminal_state_absent");
  });

  it("fails when a log does not match its pinned terminal hash", () => {
    const report = verifyLinkedAuditLogs(
      [
        { label: "platform", events: platformLog, expectedTerminalHash: `sha256:${"0".repeat(64)}` },
        { label: "signer", events: signerLog },
      ],
      { intentIds: ["int_1", "pay_1"], requiredKinds, expectedTerminalState: "DELIVERED" },
    );
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.code)).toContain("terminal_hash_mismatch");
  });
});
