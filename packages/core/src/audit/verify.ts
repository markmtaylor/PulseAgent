import { digestOf } from "../digest.js";
import { TERMINAL_STATES, type AuditEvent, type IntentState } from "../types.js";
import { AUDIT_GENESIS_HASH, readEventsFile } from "./log.js";

/**
 * Legal state transitions. A record that moves an intent anywhere else is a
 * finding: hash integrity says a log was not edited, which is a different claim
 * from the lifecycle it describes being possible.
 *
 * `RECONCILING` is reachable from any in-flight state and can resolve in any
 * direction, because an unknown submission outcome is exactly the case where the
 * next observation could be inclusion, revert or a denial after reconciliation.
 * What it must never do is resolve by starting a second payment, which is
 * enforced by the store's nonce and authorization bindings rather than here.
 */
const LEGAL_TRANSITIONS: Readonly<Record<IntentState, readonly IntentState[]>> = {
  QUOTED: ["QUOTED", "POLICY_APPROVED", "DENIED", "EXPIRED"],
  // A buyer may go straight to AUTHORIZED: the reservation is taken on the other
  // side of the custody boundary and recorded in the signer's own log, so
  // RESERVED is not an event the buyer ever observes.
  POLICY_APPROVED: ["POLICY_APPROVED", "RESERVED", "AUTHORIZED", "DENIED", "EXPIRED"],
  RESERVED: ["RESERVED", "AUTHORIZED", "DENIED", "EXPIRED", "RECONCILING"],
  // AUTHORIZED to FINALIZED covers recovery: an authorization whose settlement is
  // found already complete was never observed being submitted by this process.
  AUTHORIZED: ["AUTHORIZED", "SUBMITTED", "FINALIZED", "DENIED", "EXPIRED", "RECONCILING"],
  // SUBMITTED to FINALIZED is one step because verification establishes inclusion
  // and finality in a single read. INCLUDED is recorded only where finality is
  // still outstanding.
  SUBMITTED: ["SUBMITTED", "INCLUDED", "FINALIZED", "REVERTED", "RECONCILING"],
  INCLUDED: ["INCLUDED", "FINALIZED", "REVERTED", "RECONCILING"],
  FINALIZED: ["FINALIZED", "DELIVERED", "RECONCILING"],
  RECONCILING: ["RECONCILING", "SUBMITTED", "INCLUDED", "FINALIZED", "REVERTED", "DELIVERED", "DENIED", "EXPIRED"],
  DELIVERED: [],
  DENIED: [],
  EXPIRED: [],
  REVERTED: [],
};

/** The first state an intent may be recorded in. */
const INITIAL_STATES: readonly IntentState[] = ["QUOTED", "POLICY_APPROVED", "DENIED"];

/** Record kinds whose order relative to each other is part of the contract. */
const SETTLEMENT_VERIFIED_KIND = "settlement.verified";
const RESULT_DELIVERED_KIND = "result.delivered";

export interface AuditFinding {
  readonly severity: "error" | "warning";
  readonly code: string;
  readonly message: string;
  readonly seq?: number;
}

export interface AuditVerifyExpectation {
  /**
   * Require every intent in this log to show a complete lifecycle: a legal
   * initial state and a terminal one.
   *
   * Off by default, because one payment is recorded across several logs and
   * under more than one id. The signer's log ends an intent at AUTHORIZED, and
   * the seller's records for a payment begin at FINALIZED — each correct in
   * place, each incomplete alone. Use {@link verifyLinkedAuditLogs} for the
   * whole lifecycle; this flag is for a log that should contain all of it.
   */
  readonly requireCompleteLifecycle?: boolean;
  /**
   * Terminal `eventHash` recorded somewhere outside this file, typically an
   * exported manifest. Without it, truncation of the tail is undetectable.
   */
  readonly expectedTerminalHash?: string;
  /** Intent ids that must each reach a terminal state in this log. */
  readonly expectedIntentIds?: readonly string[];
  /** Terminal state each of those intents must reach. */
  readonly expectedTerminalState?: IntentState;
}

export interface AuditVerifyReport {
  readonly ok: boolean;
  readonly events: number;
  readonly terminalHash: string | undefined;
  readonly findings: readonly AuditFinding[];
  readonly intents: readonly {
    readonly intentId: string;
    readonly states: readonly IntentState[];
    readonly terminalState: IntentState | undefined;
    readonly hasSettlement: boolean;
    readonly hasDelivery: boolean;
  }[];
  /**
   * Always true: a log the verifier can read is a log a writer could have
   * rewritten. Carried in the report so no caller can present this check as
   * independent tamper-proofing.
   */
  readonly locallyRewritable: true;
}

/**
 * Checks a log's structure: sequence numbering, hash chain, intent linkage and
 * terminal completeness.
 *
 * What this proves: no interior record was edited, reordered or removed relative
 * to the records that follow it, and the intents named reached a terminal state
 * with the settlement and delivery records that state requires.
 *
 * What it cannot prove: that the file is the original one. A writer with access
 * can rebuild a consistent chain from scratch, or lop off the tail. Supply
 * `expectedTerminalHash` from an external manifest to close the truncation gap,
 * and treat independent anchoring as a separate, later control.
 */
export function verifyAuditEvents(
  events: readonly AuditEvent[],
  expectation: AuditVerifyExpectation = {},
): AuditVerifyReport {
  const findings: AuditFinding[] = [];
  let prevHash = AUDIT_GENESIS_HASH;

  for (const [index, event] of events.entries()) {
    const expectedSeq = index + 1;
    if (event.seq !== expectedSeq) {
      findings.push({
        severity: "error",
        code: "sequence_gap",
        message: `record at position ${String(expectedSeq)} declares seq ${String(event.seq)}`,
        seq: event.seq,
      });
    }
    if (event.prevHash !== prevHash) {
      findings.push({
        severity: "error",
        code: "chain_break",
        message: `record ${String(event.seq)} does not chain to the previous record`,
        seq: event.seq,
      });
    }
    const { eventHash, ...unhashed } = event;
    const recomputed = digestOf(unhashed);
    if (recomputed !== eventHash) {
      findings.push({
        severity: "error",
        code: "event_hash_mismatch",
        message: `record ${String(event.seq)} has been modified since it was written`,
        seq: event.seq,
      });
    }
    prevHash = eventHash;
  }

  // Per-intent lifecycle. Ordering is checked as the log is read, in sequence
  // order, so "delivered before settled" and "anything after a terminal state"
  // are both caught rather than being flattened into a set membership test.
  interface IntentTrack {
    states: IntentState[];
    settlementVerifiedAtSeq: number | undefined;
    deliveredAtSeq: number | undefined;
    terminalAtSeq: number | undefined;
    terminalState: IntentState | undefined;
    sawPolicyRevision: boolean;
  }
  const byIntent = new Map<string, IntentTrack>();

  for (const event of events) {
    if (event.intentId === undefined) {
      if (event.state !== undefined) {
        findings.push({
          severity: "error",
          code: "state_without_intent",
          message: `record ${String(event.seq)} advances a state but names no intent`,
          seq: event.seq,
        });
      }
      continue;
    }
    const track: IntentTrack =
      byIntent.get(event.intentId) ??
      {
        states: [],
        settlementVerifiedAtSeq: undefined,
        deliveredAtSeq: undefined,
        terminalAtSeq: undefined,
        terminalState: undefined,
        sawPolicyRevision: false,
      };

    if (track.terminalAtSeq !== undefined) {
      findings.push({
        severity: "error",
        code: "record_after_terminal_state",
        message:
          `intent ${event.intentId} reached terminal state ${String(track.terminalState)} at record ` +
          `${String(track.terminalAtSeq)} but record ${String(event.seq)} continues it`,
        seq: event.seq,
      });
    }

    if (event.policyRevision !== undefined) track.sawPolicyRevision = true;

    if (event.state !== undefined) {
      const previous = track.states[track.states.length - 1];
      if (previous === undefined) {
        if (expectation.requireCompleteLifecycle === true && !INITIAL_STATES.includes(event.state)) {
          findings.push({
            severity: "error",
            code: "illegal_initial_state",
            message: `intent ${event.intentId} starts in ${event.state}, which is not an initial state`,
            seq: event.seq,
          });
        }
      } else if (!LEGAL_TRANSITIONS[previous].includes(event.state)) {
        findings.push({
          severity: "error",
          code: "illegal_state_transition",
          message: `intent ${event.intentId} moves from ${previous} to ${event.state}, which is not permitted`,
          seq: event.seq,
        });
      }
      track.states.push(event.state);
      if (TERMINAL_STATES.includes(event.state)) {
        track.terminalAtSeq = event.seq;
        track.terminalState = event.state;
      }
    }

    if (event.kind === SETTLEMENT_VERIFIED_KIND && track.settlementVerifiedAtSeq === undefined) {
      track.settlementVerifiedAtSeq = event.seq;
    }
    if (event.kind === RESULT_DELIVERED_KIND) {
      if (track.deliveredAtSeq === undefined) track.deliveredAtSeq = event.seq;
      if (track.settlementVerifiedAtSeq === undefined) {
        findings.push({
          severity: "error",
          code: "delivery_before_settlement",
          message:
            `intent ${event.intentId} records a delivery at record ${String(event.seq)} with no verified ` +
            `settlement before it`,
          seq: event.seq,
        });
      }
    }

    byIntent.set(event.intentId, track);
  }

  const intents = [...byIntent.entries()].map(([intentId, track]) => ({
    intentId,
    states: track.states,
    terminalState: track.terminalState,
    hasSettlement: track.settlementVerifiedAtSeq !== undefined,
    hasDelivery: track.deliveredAtSeq !== undefined,
  }));

  for (const [intentId, track] of byIntent.entries()) {
    if (track.terminalState === undefined && expectation.requireCompleteLifecycle === true) {
      findings.push({
        severity: "error",
        code: "intent_not_terminal",
        message: `intent ${intentId} never reached a terminal state`,
      });
      continue;
    }
    if (!track.sawPolicyRevision) {
      findings.push({
        severity: "error",
        code: "missing_policy_linkage",
        message: `intent ${intentId} has no record naming the policy revision it was decided under`,
      });
    }
    if (track.terminalState === "DELIVERED" && track.settlementVerifiedAtSeq === undefined) {
      // Whichever actor records a delivery must have verified the settlement
      // first, in its own log, where sequence numbers make "first" meaningful.
      findings.push({
        severity: "error",
        code: "delivery_without_settlement",
        message: `intent ${intentId} reached DELIVERED with no verified settlement recorded before it`,
      });
    }
  }

  for (const intentId of expectation.expectedIntentIds ?? []) {
    const found = intents.find((intent) => intent.intentId === intentId);
    if (!found) {
      findings.push({
        severity: "error",
        code: "intent_absent",
        message: `expected intent ${intentId} has no records in this log`,
      });
      continue;
    }
    if (expectation.expectedTerminalState && found.terminalState !== expectation.expectedTerminalState) {
      findings.push({
        severity: "error",
        code: "unexpected_terminal_state",
        message:
          `intent ${intentId} ended in ${String(found.terminalState)} but ` +
          `${expectation.expectedTerminalState} was expected`,
      });
    }
  }

  const terminalHash = events.length === 0 ? undefined : events[events.length - 1]?.eventHash;
  if (expectation.expectedTerminalHash !== undefined) {
    if (terminalHash !== expectation.expectedTerminalHash) {
      findings.push({
        severity: "error",
        code: "terminal_hash_mismatch",
        message:
          "log head does not match the expected terminal hash; records may have been truncated, " +
          "replaced or appended after the manifest was written",
      });
    }
  } else {
    findings.push({
      severity: "warning",
      code: "no_external_anchor",
      message:
        "no expected terminal hash was supplied, so truncation of the log's tail cannot be detected",
    });
  }

  return {
    ok: findings.every((finding) => finding.severity !== "error"),
    events: events.length,
    terminalHash,
    findings,
    intents,
    locallyRewritable: true,
  };
}

/** {@link verifyAuditEvents} over a log file on disk. */
export async function verifyAuditFile(
  filePath: string,
  expectation: AuditVerifyExpectation = {},
): Promise<AuditVerifyReport> {
  return verifyAuditEvents(await readEventsFile(filePath), expectation);
}

/** One named audit log taking part in a linkage check. */
export interface LinkedAuditLog {
  /** Which process wrote it, e.g. `platform` or `signer`. */
  readonly label: string;
  readonly events: readonly AuditEvent[];
  /** Terminal hash from an external manifest, when one was recorded. */
  readonly expectedTerminalHash?: string;
}

export interface LinkageExpectation {
  /**
   * Every id this payment is recorded under: the buyer's intent id, and the
   * derived correlation id the seller and the verifier use. They name one
   * lifecycle recorded by processes that do not share an id space.
   */
  readonly intentIds: readonly string[];
  /**
   * Stages that must be recorded somewhere across the logs for this payment.
   *
   * An entry may be a list of alternatives, because one stage can honestly be
   * recorded in more than one way. A payment whose response was lost has no
   * observed submission and no verified delivery — it has an unresolved
   * submission and a recovered delivery — and the fix for that is to accept the
   * record that was actually made, not to write one that was not observed.
   */
  readonly requiredKinds: readonly (string | readonly string[])[];
  /** Terminal state the payment must reach in some log. */
  readonly expectedTerminalState: IntentState;
}

export interface LinkageReport {
  readonly ok: boolean;
  readonly perLog: readonly { readonly label: string; readonly report: AuditVerifyReport }[];
  readonly findings: readonly AuditFinding[];
  /** Where each required kind was found, for operator-facing evidence. */
  readonly kinds: readonly { readonly kind: string; readonly label: string | undefined }[];
}

/**
 * Verifies several audit logs and the linkage between them for one intent.
 *
 * One payment spans two hash chains, because the signer keeps its own state: it
 * records the authorization it issued, while the platform records the quote,
 * the submission, the verified settlement and the delivery. Each chain is
 * verified on its own terms, then this checks that the intent's required records
 * actually exist across them and that it reached the expected terminal state
 * somewhere. Two consistent chains that between them never record a verified
 * settlement are a failure, not a pass.
 *
 * Cross-log ordering is deliberately not inferred from timestamps: separate
 * processes have separate clocks, and a wall-clock comparison between two chains
 * would be a guess presented as a check. Ordering is enforced within each chain,
 * where sequence numbers make it real.
 */
export function verifyLinkedAuditLogs(
  logs: readonly LinkedAuditLog[],
  expectation: LinkageExpectation,
): LinkageReport {
  const findings: AuditFinding[] = [];
  const perLog = logs.map((log) => ({
    label: log.label,
    report: verifyAuditEvents(log.events, {
      ...(log.expectedTerminalHash === undefined ? {} : { expectedTerminalHash: log.expectedTerminalHash }),
    }),
  }));

  for (const entry of perLog) {
    for (const finding of entry.report.findings) {
      if (finding.severity === "error") {
        findings.push({ ...finding, message: `${entry.label}: ${finding.message}` });
      }
    }
  }

  const ids = new Set(expectation.intentIds);
  const belongs = (event: AuditEvent): boolean => event.intentId !== undefined && ids.has(event.intentId);

  const kinds = expectation.requiredKinds.map((requirement) => {
    const alternatives = typeof requirement === "string" ? [requirement] : requirement;
    const match = alternatives
      .map((kind) => ({
        kind,
        label: logs.find((log) => log.events.some((event) => belongs(event) && event.kind === kind))?.label,
      }))
      .find((candidate) => candidate.label !== undefined);
    if (!match) {
      findings.push({
        severity: "error",
        code: "missing_linked_record",
        message: `no log records ${alternatives.join(" or ")} for this payment`,
      });
    }
    return { kind: match?.kind ?? alternatives.join(" or "), label: match?.label };
  });

  const states = logs.flatMap((log) =>
    log.events.filter((event) => belongs(event) && event.state !== undefined).map((event) => event.state as IntentState),
  );
  if (!states.includes(expectation.expectedTerminalState)) {
    findings.push({
      severity: "error",
      code: "linked_terminal_state_absent",
      message: `this payment never reached ${expectation.expectedTerminalState} in any log`,
    });
  }

  // Id membership alone is not linkage. Two unrelated payments, one per id,
  // would otherwise pass as a single lifecycle simply because both ids were
  // supplied — so the immutable facts the records carry must agree.
  const CORRELATING_FIELDS = [
    "quoteId",
    "authorizationNonce",
    "requestDigest",
    "amountAtomic",
    "payer",
    "asset",
    "payTo",
    "transactionHash",
    "signatureDigest",
    "resultDigest",
    "authorizationDigest",
  ] as const;
  const observed = new Map<string, Set<string>>();
  for (const log of logs) {
    for (const event of log.events) {
      if (!belongs(event)) continue;
      for (const field of CORRELATING_FIELDS) {
        const value = (event.payload as Record<string, unknown>)[field];
        if (typeof value !== "string") continue;
        const values = observed.get(field) ?? new Set<string>();
        values.add(field === "payer" ? value.toLowerCase() : value);
        observed.set(field, values);
      }
    }
  }
  for (const [field, values] of observed) {
    if (values.size > 1) {
      findings.push({
        severity: "error",
        code: "contradictory_linkage",
        message:
          `records joined under these ids disagree about ${field} ` +
          `(${[...values].join(", ")}), so they do not describe one payment`,
      });
    }
  }
  if (!observed.has("quoteId")) {
    findings.push({
      severity: "error",
      code: "linkage_not_established",
      message: "no record under these ids names the quote, so the link between them is unverifiable",
    });
  }

  // Policy revision is compared per actor, not globally. Each participant acts
  // under its own operator configuration — the buyer's spending policy and the
  // seller's pricing configuration are different documents with different
  // revisions — so requiring one value across all of them would conflate them.
  // What must hold is that no single actor changed policy mid-payment.
  const revisionsByActor = new Map<string, Set<string>>();
  for (const log of logs) {
    for (const event of log.events) {
      if (!belongs(event) || event.policyRevision === undefined) continue;
      const seen = revisionsByActor.get(event.actor) ?? new Set<string>();
      seen.add(event.policyRevision);
      revisionsByActor.set(event.actor, seen);
    }
  }
  for (const [actor, revisions] of revisionsByActor) {
    if (revisions.size > 1) {
      findings.push({
        severity: "error",
        code: "contradictory_linkage",
        message:
          `the ${actor} recorded this payment under more than one policy revision ` +
          `(${[...revisions].join(", ")}), so it was decided under two different policies`,
      });
    }
  }

  // Each stage must actually carry the facts that tie it to the next one. A
  // record of the right kind with the field missing proves only that something
  // was written, so "absent" is a finding rather than a pass.
  const STAGE_FIELDS: Readonly<Record<string, readonly string[]>> = {
    "signer.reservation.held": ["authorizationNonce", "asset", "payTo", "amountAtomic"],
    "signer.authorization.signed": ["signatureDigest", "authorizationDigest"],
    "settlement.verified": ["transactionHash", "authorizationNonce", "amountAtomic"],
    "result.delivered": ["resultDigest", "transactionHash"],
  };
  const fieldAt = (kind: string, field: string): string | undefined => {
    for (const log of logs) {
      for (const event of log.events) {
        if (!belongs(event) || event.kind !== kind) continue;
        const value = (event.payload as Record<string, unknown>)[field];
        if (typeof value === "string") return value;
      }
    }
    return undefined;
  };
  for (const [kind, fields] of Object.entries(STAGE_FIELDS)) {
    const present = logs.some((log) => log.events.some((event) => belongs(event) && event.kind === kind));
    if (!present) continue;
    for (const field of fields) {
      if (fieldAt(kind, field) === undefined) {
        findings.push({
          severity: "error",
          code: "incomplete_stage_record",
          message: `the ${kind} record for this payment does not carry ${field}, so it links to nothing`,
        });
      }
    }
  }

  // Reservation -> signature -> transfer -> result, each joined by a fact the
  // previous stage fixed, rather than by a quote id and a correlation id alone.
  const reservedNonce = fieldAt("signer.reservation.held", "authorizationNonce");
  const settledNonce = fieldAt("settlement.verified", "authorizationNonce");
  if (reservedNonce !== undefined && settledNonce !== undefined && reservedNonce.toLowerCase() !== settledNonce.toLowerCase()) {
    findings.push({
      severity: "error",
      code: "stage_linkage_broken",
      message: "the settlement consumed a different authorization nonce than the one reserved and signed",
    });
  }
  const settledTx = fieldAt("settlement.verified", "transactionHash");
  const deliveredTx = fieldAt("result.delivered", "transactionHash");
  if (settledTx !== undefined && deliveredTx !== undefined && settledTx.toLowerCase() !== deliveredTx.toLowerCase()) {
    findings.push({
      severity: "error",
      code: "stage_linkage_broken",
      message: "the delivered result cites a different settlement transaction than the one verified",
    });
  }

  // When several ids are supplied, some record must tie them together rather
  // than the caller simply asserting they belong to each other.
  if (expectation.intentIds.length > 1) {
    const tied = logs.some((log) =>
      log.events.some((event) => {
        if (event.intentId === undefined || !ids.has(event.intentId)) return false;
        const correlationId = (event.payload as { correlationId?: unknown }).correlationId;
        return typeof correlationId === "string" && ids.has(correlationId) && correlationId !== event.intentId;
      }),
    );
    if (!tied) {
      findings.push({
        severity: "error",
        code: "linkage_not_established",
        message:
          "no record names both of this payment's ids, so the claim that they are the same payment " +
          "rests only on the caller having supplied them together",
      });
    }
  }

  return { ok: findings.length === 0, perLog, findings, kinds };
}
