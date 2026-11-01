import { mkdir, open, readFile } from "node:fs/promises";
import path from "node:path";
import { canonicalize } from "../canonical.js";
import { digestOf, sha256Hex } from "../digest.js";
import { AuditEventSchema, type AuditEvent, type IntentState } from "../types.js";
import type { DurableStore } from "../state/store.js";
import { assertNoSecretMaterial, redactPayload } from "./redact.js";

/** `prevHash` of the first record in a log. */
export const AUDIT_GENESIS_HASH = sha256Hex("pulseagent-audit-genesis-v1");

export interface AuditAppend {
  readonly actor: AuditEvent["actor"];
  readonly kind: string;
  readonly intentId?: string;
  readonly policyRevision?: string;
  readonly operatorApprovalId?: string;
  readonly state?: IntentState;
  readonly payload: Record<string, unknown>;
}

/**
 * Append-only, hash-chained audit log.
 *
 * Records live in the durable store, where each append allocates its sequence
 * number and reads the chain head inside one transaction. Two processes writing
 * at once therefore cannot be handed the same sequence number or the same
 * predecessor, so the chain stays consistent without electing a single writer.
 *
 * Each record carries the previous record's `eventHash`, which makes any edit to
 * or removal of an interior record detectable from the records that follow it.
 * What chaining does *not* do is stop whoever can write the database from
 * rebuilding the whole chain or dropping its tail. Detecting that needs the
 * terminal hash held somewhere else, which is what {@link exportToFile}'s
 * manifest is for: a locally rewritable log is not independently tamper-proof.
 *
 * Appends fail closed. If a record cannot be committed, the caller's side effect
 * must not happen.
 */
export class AuditLog {
  private readonly store: DurableStore;

  constructor(store: DurableStore) {
    this.store = store;
  }

  /** The chain head an external manifest should pin, or the genesis constant. */
  get terminalHash(): string {
    return this.store.readAuditHead()?.eventHash ?? AUDIT_GENESIS_HASH;
  }

  /** Number of records written so far. */
  get length(): number {
    return this.store.readAuditHead()?.seq ?? 0;
  }

  /**
   * Appends one record, redacting its payload first.
   *
   * Throws if the payload still carries secret or replayable material, or if the
   * record cannot be committed.
   */
  append(entry: AuditAppend): AuditEvent {
    const payload = redactPayload(entry.payload);
    assertNoSecretMaterial(payload, `audit record ${entry.kind}`);

    return this.store.appendAuditEvent((seq, prevHash) => {
      const unhashed = {
        schemaVersion: 1 as const,
        seq,
        at: new Date().toISOString(),
        actor: entry.actor,
        kind: entry.kind,
        ...(entry.intentId === undefined ? {} : { intentId: entry.intentId }),
        ...(entry.policyRevision === undefined ? {} : { policyRevision: entry.policyRevision }),
        ...(entry.operatorApprovalId === undefined ? {} : { operatorApprovalId: entry.operatorApprovalId }),
        ...(entry.state === undefined ? {} : { state: entry.state }),
        payload,
        prevHash,
      };
      return AuditEventSchema.parse({ ...unhashed, eventHash: digestOf(unhashed) });
    }, AUDIT_GENESIS_HASH);
  }

  /** Every record currently in the log. */
  read(): AuditEvent[] {
    return this.store.readAuditEvents();
  }

  /**
   * Writes the log to `filePath` as one canonical JSON record per line.
   *
   * The exported file is the artifact a third party inspects and `audit:verify`
   * reads. Pin the returned `terminalHash` outside the file; without it a
   * verifier cannot tell a complete log from one whose tail was removed.
   */
  async exportToFile(filePath: string): Promise<{ events: number; terminalHash: string; filePath: string }> {
    const resolved = path.resolve(filePath);
    await mkdir(path.dirname(resolved), { recursive: true });
    const events = this.read();
    const body = events.map((event) => canonicalize(event)).join("\n");
    const handle = await open(resolved, "w", 0o600);
    try {
      await handle.writeFile(events.length === 0 ? "" : `${body}\n`, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    return {
      events: events.length,
      terminalHash: events[events.length - 1]?.eventHash ?? AUDIT_GENESIS_HASH,
      filePath: resolved,
    };
  }
}

/** Parses an exported log file into records, rejecting malformed lines. */
export async function readEventsFile(filePath: string): Promise<AuditEvent[]> {
  let raw: string;
  try {
    raw = await readFile(filePath, "utf8");
  } catch (error) {
    if (error instanceof Error && (error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(`audit log ${filePath} does not exist`);
    }
    throw error;
  }
  const events: AuditEvent[] = [];
  for (const [index, line] of raw.split("\n").entries()) {
    if (line.trim() === "") continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      throw new Error(`audit log ${filePath} line ${String(index + 1)} is not valid JSON`);
    }
    events.push(AuditEventSchema.parse(parsed));
  }
  return events;
}
