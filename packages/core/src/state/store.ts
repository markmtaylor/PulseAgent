import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { canonicalize } from "../canonical.js";
import { digestOf } from "../digest.js";
import { AuditEventSchema, PaymentIntentSchema, type AuditEvent, type PaymentIntent } from "../types.js";

/**
 * Durable intent, reservation, budget and audit state in a single SQLite
 * database, using SQLite's own transactions and unique constraints.
 *
 * Why SQLite rather than files: a budget check and the reservation it authorizes
 * have to be one transaction. Two processes — or two handles in one process —
 * that each read a committed total, each find room, and each then write would
 * both authorize a payment the policy allows only once. A promise chain inside
 * one object cannot prevent that; `BEGIN IMMEDIATE` can, because the second
 * writer waits for the first to commit and then re-reads inside its own
 * transaction.
 *
 * Amounts are uint256 and are stored as base-10 TEXT. All arithmetic and all
 * comparison happens in JavaScript `bigint` inside the transaction. SQLite's
 * numeric types are never used to add or compare money: its INTEGER is 64-bit
 * and its REAL is floating point, and either would silently corrupt a large
 * atomic amount.
 *
 * This is a single-host store. It gives real transactions and real uniqueness,
 * not replication, and it is not tamper-proof against whoever can write the file.
 */
export class DurableStore {
  private readonly db: DatabaseSync;
  readonly databasePath: string;

  private constructor(databasePath: string, db: DatabaseSync) {
    this.databasePath = databasePath;
    this.db = db;
  }

  /**
   * Opens (creating if absent) a store at `databasePath`, applying the schema.
   *
   * Several handles may be open at once, in this process or another; the
   * transactional methods below stay correct across all of them.
   */
  static open(databasePath: string): DurableStore {
    // `:memory:` is SQLite's own sentinel, not a path. Resolving it first would
    // create a literal file called ":memory:" in the working directory and give
    // every caller a private, non-shared database that looks shared.
    const inMemory = databasePath === ":memory:";
    const resolved = inMemory ? databasePath : path.resolve(databasePath);
    if (!inMemory) mkdirSync(path.dirname(resolved), { recursive: true });
    const db = new DatabaseSync(resolved);
    if (!inMemory) {
      // WAL lets a reader proceed during a write; FULL synchronous means a
      // committed transaction has reached the disk before we act on it. Neither
      // applies to an in-memory database, which exists only for this handle and
      // must never be used where durability or sharing is the point.
      db.exec("PRAGMA journal_mode = WAL");
      db.exec("PRAGMA synchronous = FULL");
    }
    db.exec("PRAGMA foreign_keys = ON");
    // A second writer waits here instead of failing immediately, which is what
    // makes concurrent reserve attempts serialize rather than error out.
    db.exec("PRAGMA busy_timeout = 10000");
    db.exec(SCHEMA);
    return new DurableStore(resolved, db);
  }

  close(): void {
    this.db.close();
  }

  /**
   * Runs `work` inside `BEGIN IMMEDIATE`, rolling back when it returns a
   * refusal as well as when it throws.
   *
   * A refusal has to roll back, not commit. These operations claim several rows
   * before they can tell whether the whole request is allowed — an authorization
   * binding, a nonce, an idempotency key — and committing those claims while
   * reporting failure would leave an intent bound to an authorization that was
   * never issued, so a later legitimate attempt is refused by the wreckage of
   * the first. Either the whole authorization is taken or nothing is.
   */
  private transactionAllOrNothing<T extends { readonly ok: boolean }>(work: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    let result: T;
    try {
      result = work();
    } catch (error) {
      this.rollbackQuietly();
      throw error;
    }
    if (!result.ok) {
      this.rollbackQuietly();
      return result;
    }
    this.db.exec("COMMIT");
    return result;
  }

  private rollbackQuietly(): void {
    try {
      this.db.exec("ROLLBACK");
    } catch {
      // A rollback failure must not mask the outcome being reported.
    }
  }

  /**
   * Runs `work` inside `BEGIN IMMEDIATE`, committing on return and rolling back
   * on a throw. The write lock is taken up front, so a concurrent writer waits
   * rather than reading state this transaction is about to change.
   */
  transaction<T>(work: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    let result: T;
    try {
      result = work();
    } catch (error) {
      this.rollbackQuietly();
      throw error;
    }
    this.db.exec("COMMIT");
    return result;
  }

  /**
   * Claims `value` for `(namespace, key)` exactly once, durably.
   *
   * The first caller gets `{ claimed: true }`; every later one — another handle,
   * another process, or the same process after a restart — gets the stored
   * value. This is the primitive behind single-use quotes, idempotent requests
   * and single-use authorization nonces. Keys are opaque strings compared
   * exactly, so two different ids can never collapse onto one record.
   */
  claimOnce(
    namespace: string,
    key: string,
    value: string,
  ): { claimed: true } | { claimed: false; existing: string } {
    return this.transaction(() => this.claimOnceInTransaction(namespace, key, value));
  }

  /** {@link claimOnce} for use inside a transaction this object already opened. */
  claimOnceInTransaction(
    namespace: string,
    key: string,
    value: string,
  ): { claimed: true } | { claimed: false; existing: string } {
    const inserted = this.db
      .prepare(
        "INSERT INTO claims (namespace, key, value, created_at) VALUES (?, ?, ?, ?) " +
          "ON CONFLICT (namespace, key) DO NOTHING",
      )
      .run(namespace, key, value, nowSeconds());
    if (inserted.changes === 1) return { claimed: true };
    const existing = this.readClaim(namespace, key);
    if (existing === undefined) {
      throw new Error(`claim ${namespace}/${key} conflicted but could not be read back`);
    }
    return { claimed: false, existing };
  }

  /** The value previously claimed for `(namespace, key)`, if any. */
  readClaim(namespace: string, key: string): string | undefined {
    const row = this.db
      .prepare("SELECT value FROM claims WHERE namespace = ? AND key = ?")
      .get(namespace, key) as { value?: string } | undefined;
    return row?.value;
  }

  /** Writes an intent record, validating it first. */
  putIntent(intent: PaymentIntent): void {
    const parsed = PaymentIntentSchema.parse(intent);
    this.transaction(() => this.putIntentInTransaction(parsed));
  }

  /** {@link putIntent} for use inside an open transaction. */
  putIntentInTransaction(intent: PaymentIntent): void {
    const parsed = PaymentIntentSchema.parse(intent);
    this.db
      .prepare(
        "INSERT INTO intents (intent_id, record, state, updated_at) VALUES (?, ?, ?, ?) " +
          "ON CONFLICT (intent_id) DO UPDATE SET record = excluded.record, state = excluded.state, " +
          "updated_at = excluded.updated_at",
      )
      .run(parsed.intentId, canonicalize(parsed), parsed.state, nowSeconds());
  }

  /** Reads an intent record, or undefined when there is none. */
  getIntent(intentId: string): PaymentIntent | undefined {
    const row = this.db.prepare("SELECT record FROM intents WHERE intent_id = ?").get(intentId) as
      | { record?: string }
      | undefined;
    if (row?.record === undefined) return undefined;
    return PaymentIntentSchema.parse(JSON.parse(row.record));
  }

  /** Every stored intent id, oldest update first. Used by startup reconciliation. */
  listIntentIds(): string[] {
    const rows = this.db.prepare("SELECT intent_id FROM intents ORDER BY updated_at ASC").all() as {
      intent_id: string;
    }[];
    return rows.map((row) => row.intent_id);
  }

  /** Intents in a given state, for reconciliation of unresolved submissions. */
  listIntentsInState(state: PaymentIntent["state"]): PaymentIntent[] {
    const rows = this.db
      .prepare("SELECT record FROM intents WHERE state = ? ORDER BY updated_at ASC")
      .all(state) as { record: string }[];
    return rows.map((row) => PaymentIntentSchema.parse(JSON.parse(row.record)));
  }

  /**
   * Applies `mutate` to an intent and persists the result in one transaction, so
   * two concurrent updates cannot each overwrite the other's change.
   */
  updateIntent(intentId: string, mutate: (current: PaymentIntent) => PaymentIntent): PaymentIntent {
    return this.transaction(() => {
      const current = this.getIntent(intentId);
      if (!current) throw new Error(`intent ${intentId} does not exist`);
      const next = PaymentIntentSchema.parse(mutate(current));
      if (next.intentId !== current.intentId) {
        throw new Error("updateIntent must not change the intent id");
      }
      this.putIntentInTransaction(next);
      return next;
    });
  }

  /** Committed atomic units for one budget scope: settled plus still in flight. */
  readCommittedSpend(scope: BudgetScope): bigint {
    const row = this.db
      .prepare(
        "SELECT committed_atomic FROM budget WHERE principal_id = ? AND policy_revision = ? AND asset = ?",
      )
      .get(scope.principalId, scope.policyRevision, normalizeAsset(scope.asset)) as
      | { committed_atomic?: string }
      | undefined;
    return row?.committed_atomic === undefined ? 0n : parseAtomic(row.committed_atomic, "budget.committed_atomic");
  }

  /**
   * Checks every limit and takes the whole reservation in one transaction.
   *
   * A payment commits more than one bounded resource: the token amount, and the
   * worst-case native gas a sponsor may spend on its behalf. Those are separate
   * budgets with separate ceilings, and they are reserved together — either all
   * legs are committed or none is, so a payment can never be half-authorized.
   *
   * On success the amounts are committed before the caller signs anything, and
   * they stay committed while the payment is in flight: an unresolved submission
   * keeps consuming budget instead of freeing it for a second attempt.
   *
   * A repeat call with the same idempotency key returns the original reservation
   * **only if every immutable field still matches**. Principal, policy revision
   * and the exact set of legs are bound into a digest the first call records, so
   * a second call that keeps the ids and changes the amount, the asset or the
   * principal is rejected rather than being handed the earlier reservation. A
   * caller is never relied upon to notice that the amount it got back differs
   * from the amount it asked for.
   *
   * Every comparison is `bigint`. SQLite never adds or compares an amount.
   */
  reserveBudget(request: BudgetReservationRequest): BudgetReservationResult {
    const prepared = prepareLegs(request);
    return this.transactionAllOrNothing<BudgetReservationResult>(() =>
      this.reserveInTransaction(request, prepared),
    );
  }

  /**
   * Binds an intent to one immutable authorization and reserves its budget, in a
   * single transaction.
   *
   * This is the signing boundary's guard, and it exists because reserving by
   * idempotency key alone is not enough. A caller that repeats an intent with a
   * fresh authorization nonce keeps the same reservation while asking for a
   * second, independently spendable signature; three such calls against one
   * 100-unit reservation authorize 300 units. So the whole authorization —
   * nonce, validity window, domain, payer, payee, amount, quote and request
   * identity, policy revision — is digested and bound to the intent here:
   *
   * - first call for an intent: the digest is recorded and the budget reserved
   * - exact repeat: reports `replayed`, creating no new spending capability
   * - anything changed, a different nonce above all: rejected
   *
   * The authorization nonce is additionally claimed globally, so it cannot be
   * reused under a different intent either.
   */
  bindAuthorization(request: AuthorizationBindRequest): AuthorizationBindResult {
    const prepared = prepareLegs(request);
    return this.transactionAllOrNothing<AuthorizationBindResult>(() => {
      const bound = this.claimOnceInTransaction("authorization", request.intentId, request.authorizationDigest);
      if (!bound.claimed && bound.existing !== request.authorizationDigest) {
        return {
          ok: false,
          code: "authorization_already_bound",
          reason:
            "this intent is already bound to a different authorization; a changed nonce, amount, " +
            "validity window, domain or payee requires a new intent",
        };
      }

      const nonceKey = `${request.payer.toLowerCase()}:${request.authorizationNonce.toLowerCase()}`;
      const nonce = this.claimOnceInTransaction("auth-nonce", nonceKey, request.intentId);
      if (!nonce.claimed && nonce.existing !== request.intentId) {
        return {
          ok: false,
          code: "nonce_bound_to_other_intent",
          reason: "this authorization nonce has already been issued under another intent",
        };
      }

      const reservation = this.reserveInTransaction(request, prepared);
      if (!reservation.ok) return reservation;
      return { ...reservation, replayed: reservation.replayed || !bound.claimed };
    });
  }

  /** Shared reservation body. Must be called inside an open transaction. */
  private reserveInTransaction(
    request: BudgetReservationRequest,
    prepared: PreparedLegs,
  ): BudgetReservationResult {
    const bindingDigest = digestOf({
      principalId: request.principalId,
      policyRevision: request.policyRevision,
      intentId: request.intentId,
      idempotencyKey: request.idempotencyKey,
      legs: prepared.map((leg) => ({
        asset: leg.asset,
        amountAtomic: leg.amount.toString(10),
        maxAmountPerPayment: leg.perPayment.toString(10),
        totalBudget: leg.total.toString(10),
      })),
    });

    const binding = this.claimOnceInTransaction("reservation-binding", request.intentId, bindingDigest);
    if (!binding.claimed && binding.existing !== bindingDigest) {
      return {
        ok: false,
        code: "reservation_binding_changed",
        reason:
          "this intent already holds a reservation for different immutable terms; principal, policy " +
          "revision, asset, amount and limits may not change on a retry",
      };
    }

    const claim = this.claimOnceInTransaction("idempotency", request.idempotencyKey, request.intentId);
    if (!claim.claimed && claim.existing !== request.intentId) {
      return {
        ok: false,
        code: "idempotency_key_bound_to_other_intent",
        reason: `idempotency key already belongs to intent ${claim.existing}`,
      };
    }

    const existing = this.readReservationLegs(request.intentId);
    if (existing.length > 0) {
      const reservationId = existing[0]?.reservationId;
      if (reservationId === undefined) throw new Error("reservation row is missing its id");
      return {
        ok: true,
        reservationId,
        legs: existing.map((leg) => ({ asset: leg.asset, amountAtomic: leg.amountAtomic })),
        replayed: true,
      };
    }

    for (const leg of prepared) {
      if (leg.amount <= 0n) {
        return {
          ok: false,
          code: "amount_not_positive",
          reason: `reservation for ${leg.asset} must be a positive amount`,
        };
      }
      if (leg.amount > leg.perPayment) {
        return {
          ok: false,
          code: "amount_over_per_payment_limit",
          reason:
            `${leg.asset} amount ${leg.amount.toString(10)} exceeds the per-payment limit of ` +
            `${leg.perPayment.toString(10)} atomic units`,
        };
      }
      const committedAfter = this.readCommittedSpend({ ...request, asset: leg.asset }) + leg.amount;
      if (committedAfter > leg.total) {
        return {
          ok: false,
          code: "budget_exhausted",
          reason:
            `reserving ${leg.amount.toString(10)} of ${leg.asset} would commit ` +
            `${committedAfter.toString(10)} against a total budget of ${leg.total.toString(10)}`,
        };
      }
    }

    const committedLegs: { asset: string; amountAtomic: string }[] = [];
    for (const leg of prepared) {
      const committedAfter = this.readCommittedSpend({ ...request, asset: leg.asset }) + leg.amount;
      this.db
        .prepare(
          "INSERT INTO reservations (reservation_id, intent_id, asset, principal_id, policy_revision, " +
            "amount_atomic, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .run(
          request.reservationId,
          request.intentId,
          leg.asset,
          request.principalId,
          request.policyRevision,
          leg.amount.toString(10),
          nowSeconds(),
        );
      this.db
        .prepare(
          "INSERT INTO budget (principal_id, policy_revision, asset, committed_atomic) VALUES (?, ?, ?, ?) " +
            "ON CONFLICT (principal_id, policy_revision, asset) DO UPDATE SET " +
            "committed_atomic = excluded.committed_atomic",
        )
        .run(request.principalId, request.policyRevision, leg.asset, committedAfter.toString(10));
      committedLegs.push({ asset: leg.asset, amountAtomic: leg.amount.toString(10) });
    }

    return { ok: true, reservationId: request.reservationId, legs: committedLegs, replayed: false };
  }

  /**
   * Allocates the next transaction nonce for a sender, durably and monotonically.
   *
   * Asking the node for its pending count is not sufficient on its own. A
   * transaction can be signed and then fail to reach the node — a dropped
   * connection, a timeout, a crash between the two — and the node's pending
   * count stays where it was. The next settlement then gets the same nonce and
   * either replaces the earlier transaction or is rejected, and in the first case
   * a payment that may already be in flight is silently displaced.
   *
   * So the allocation is `max(node pending, last allocated + 1)`, recorded before
   * the transaction is signed. The stored value only moves forward.
   *
   * @param senderKey Network plus sender address.
   * @param nodePendingNonce The node's pending transaction count for that sender.
   * @returns The nonce to use.
   */
  allocateSenderNonce(senderKey: string, nodePendingNonce: number): number {
    if (!Number.isSafeInteger(nodePendingNonce) || nodePendingNonce < 0) {
      throw new Error("a pending nonce must be a non-negative integer");
    }
    return this.transaction(() => {
      const row = this.db
        .prepare("SELECT next_nonce FROM sender_nonces WHERE sender_key = ?")
        .get(senderKey) as { next_nonce?: number } | undefined;
      const stored = row?.next_nonce ?? 0;
      const allocated = Math.max(nodePendingNonce, stored);
      this.db
        .prepare(
          "INSERT INTO sender_nonces (sender_key, next_nonce) VALUES (?, ?) " +
            "ON CONFLICT (sender_key) DO UPDATE SET next_nonce = excluded.next_nonce",
        )
        .run(senderKey, allocated + 1);
      return allocated;
    });
  }

  /**
   * Claims the right to broadcast one authorization and allocates its sender
   * nonce, in a single transaction.
   *
   * Allocating the nonce before taking the claim loses a nonce every time a
   * duplicate attempt is beaten to it: the loser has already moved the counter,
   * so the winner's transaction and the next one are separated by a gap, and
   * nothing will ever fill it — every later transaction from that account sits
   * behind a nonce that was never used. Doing both here means only the caller
   * that actually gets to broadcast consumes a nonce.
   *
   * The returned nonce belongs to this claim permanently. A caller that fails
   * after this point — signing throws, the send fails, the process dies — must
   * retry with the *same* nonce, which it gets by reading the claim back. That
   * is what makes a failed broadcast recoverable instead of a gap.
   *
   * @param args Claim key, the sender whose nonce to allocate, the node's
   *        pending count and the immutable terms this broadcast is for.
   * @returns The allocated nonce for the winner, or the existing record.
   */
  claimBroadcastSlot(args: {
    readonly key: string;
    readonly senderKey: string;
    readonly nodePendingNonce: number;
    readonly terms: Record<string, string>;
  }):
    | { readonly claimed: true; readonly senderNonce: number }
    | { readonly claimed: false; readonly record: BroadcastRecord } {
    return this.transaction(() => {
      const existing = this.readBroadcastInTransaction(args.key);
      if (existing) return { claimed: false, record: existing };

      const row = this.db
        .prepare("SELECT next_nonce FROM sender_nonces WHERE sender_key = ?")
        .get(args.senderKey) as { next_nonce?: number } | undefined;
      const senderNonce = Math.max(args.nodePendingNonce, row?.next_nonce ?? 0);
      this.db
        .prepare(
          "INSERT INTO sender_nonces (sender_key, next_nonce) VALUES (?, ?) " +
            "ON CONFLICT (sender_key) DO UPDATE SET next_nonce = excluded.next_nonce",
        )
        .run(args.senderKey, senderNonce + 1);
      this.db
        .prepare(
          "INSERT INTO broadcasts (key, sender_key, sender_nonce, terms, tx_hash, created_at) " +
            "VALUES (?, ?, ?, ?, NULL, ?)",
        )
        .run(args.key, args.senderKey, senderNonce, canonicalize(args.terms), nowSeconds());
      return { claimed: true, senderNonce };
    });
  }

  /** Records the hash of the transaction a claimed slot broadcast. */
  recordBroadcastHash(key: string, txHash: string): void {
    this.transaction(() => {
      const updated = this.db
        .prepare("UPDATE broadcasts SET tx_hash = ? WHERE key = ? AND (tx_hash IS NULL OR tx_hash = ?)")
        .run(txHash, key, txHash);
      if (updated.changes === 0) {
        throw new Error(`broadcast slot ${key} already recorded a different transaction hash`);
      }
    });
  }

  /** The broadcast slot for an authorization, if one has been claimed. */
  readBroadcast(key: string): BroadcastRecord | undefined {
    return this.readBroadcastInTransaction(key);
  }

  private readBroadcastInTransaction(key: string): BroadcastRecord | undefined {
    const row = this.db
      .prepare("SELECT sender_nonce, terms, tx_hash FROM broadcasts WHERE key = ?")
      .get(key) as { sender_nonce?: number; terms?: string; tx_hash?: string | null } | undefined;
    if (row?.sender_nonce === undefined || row.terms === undefined) return undefined;
    return {
      senderNonce: row.sender_nonce,
      terms: JSON.parse(row.terms) as Record<string, string>,
      txHash: row.tx_hash ?? undefined,
    };
  }

  /** Every reservation leg held for an intent. */
  readReservationLegs(
    intentId: string,
  ): { reservationId: string; asset: string; amountAtomic: string }[] {
    const rows = this.db
      .prepare(
        "SELECT reservation_id, asset, amount_atomic FROM reservations WHERE intent_id = ? ORDER BY asset ASC",
      )
      .all(intentId) as { reservation_id: string; asset: string; amount_atomic: string }[];
    return rows.map((row) => ({
      reservationId: row.reservation_id,
      asset: row.asset,
      amountAtomic: row.amount_atomic,
    }));
  }

  /**
   * Appends one audit record, allocating its sequence number and chaining it to
   * the current head inside a transaction.
   *
   * `build` receives the allocated `seq` and the head's `eventHash` and returns
   * the finished record. Two writers cannot be handed the same sequence number
   * or the same predecessor, so the chain stays single-threaded without needing
   * a single enforced writer process.
   */
  appendAuditEvent(build: (seq: number, prevHash: string) => AuditEvent, genesisHash: string): AuditEvent {
    return this.transaction(() => {
      const head = this.db
        .prepare("SELECT seq, event_hash FROM audit_events ORDER BY seq DESC LIMIT 1")
        .get() as { seq?: number; event_hash?: string } | undefined;
      const seq = (head?.seq ?? 0) + 1;
      const prevHash = head?.event_hash ?? genesisHash;
      const event = AuditEventSchema.parse(build(seq, prevHash));
      if (event.seq !== seq || event.prevHash !== prevHash) {
        throw new Error("audit record did not adopt the allocated sequence and predecessor");
      }
      this.db
        .prepare(
          "INSERT INTO audit_events (seq, event, event_hash, prev_hash, intent_id) VALUES (?, ?, ?, ?, ?)",
        )
        .run(event.seq, canonicalize(event), event.eventHash, event.prevHash, event.intentId ?? null);
      return event;
    });
  }

  /** Every audit record in sequence order. */
  readAuditEvents(): AuditEvent[] {
    const rows = this.db.prepare("SELECT event FROM audit_events ORDER BY seq ASC").all() as {
      event: string;
    }[];
    return rows.map((row) => AuditEventSchema.parse(JSON.parse(row.event)));
  }

  /** The current chain head, or undefined for an empty log. */
  readAuditHead(): { seq: number; eventHash: string } | undefined {
    const row = this.db
      .prepare("SELECT seq, event_hash FROM audit_events ORDER BY seq DESC LIMIT 1")
      .get() as { seq?: number; event_hash?: string } | undefined;
    if (row?.seq === undefined || row.event_hash === undefined) return undefined;
    return { seq: row.seq, eventHash: row.event_hash };
  }
}

/** A claimed broadcast slot: its nonce, the terms it is for, and its hash once sent. */
export interface BroadcastRecord {
  readonly senderNonce: number;
  readonly terms: Record<string, string>;
  /** Undefined until the transaction has been built and recorded. */
  readonly txHash: string | undefined;
}

/** Which budget a reservation is taken against. */
export interface BudgetScope {
  readonly principalId: string;
  readonly policyRevision: string;
  /** Asset address. Normalized to lowercase so casing cannot split a budget. */
  readonly asset: string;
}

/** One bounded resource a payment commits: a token amount, or sponsored gas. */
export interface BudgetReservationLeg {
  /** Budget key: a token address, or `native:gas` for sponsored native gas. */
  readonly asset: string;
  readonly amountAtomic: string;
  readonly maxAmountPerPayment: string;
  readonly totalBudget: string;
}

export interface BudgetReservationRequest {
  readonly principalId: string;
  readonly policyRevision: string;
  readonly intentId: string;
  readonly idempotencyKey: string;
  readonly reservationId: string;
  readonly legs: readonly BudgetReservationLeg[];
}

export type BudgetReservationResult =
  | {
      readonly ok: true;
      readonly reservationId: string;
      readonly legs: readonly { readonly asset: string; readonly amountAtomic: string }[];
      /** True when an existing reservation was returned instead of a new one. */
      readonly replayed: boolean;
    }
  | {
      readonly ok: false;
      readonly code:
        | "amount_not_positive"
        | "amount_over_per_payment_limit"
        | "budget_exhausted"
        | "idempotency_key_bound_to_other_intent"
        | "reservation_binding_changed";
      readonly reason: string;
    };

/** A reservation plus the single authorization an intent is allowed to produce. */
export interface AuthorizationBindRequest extends BudgetReservationRequest {
  /**
   * Digest over everything that determines this authorization's spending power:
   * domain, primary type, payer, payee, amount, validity window, nonce, quote
   * and request identity, policy revision and the intent's own ids. Anything
   * omitted here becomes a field a caller may change while keeping the
   * reservation, which is how one reservation turns into several signatures.
   */
  readonly authorizationDigest: string;
  /** Payer address, used to scope the global nonce claim. */
  readonly payer: string;
  /** The EIP-3009 authorization nonce this intent is bound to. */
  readonly authorizationNonce: string;
}

export type AuthorizationBindResult =
  | {
      readonly ok: true;
      readonly reservationId: string;
      readonly legs: readonly { readonly asset: string; readonly amountAtomic: string }[];
      /** True when the intent was already bound to this exact authorization. */
      readonly replayed: boolean;
    }
  | {
      readonly ok: false;
      readonly code:
        | "amount_not_positive"
        | "amount_over_per_payment_limit"
        | "budget_exhausted"
        | "idempotency_key_bound_to_other_intent"
        | "reservation_binding_changed"
        | "authorization_already_bound"
        | "nonce_bound_to_other_intent";
      readonly reason: string;
    };

const SCHEMA = `
CREATE TABLE IF NOT EXISTS intents (
  intent_id  TEXT PRIMARY KEY,
  record     TEXT NOT NULL,
  state      TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS intents_state ON intents (state, updated_at);

CREATE TABLE IF NOT EXISTS claims (
  namespace  TEXT NOT NULL,
  key        TEXT NOT NULL,
  value      TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (namespace, key)
);

CREATE TABLE IF NOT EXISTS budget (
  principal_id     TEXT NOT NULL,
  policy_revision  TEXT NOT NULL,
  asset            TEXT NOT NULL,
  committed_atomic TEXT NOT NULL,
  PRIMARY KEY (principal_id, policy_revision, asset)
);

CREATE TABLE IF NOT EXISTS reservations (
  reservation_id  TEXT NOT NULL,
  intent_id       TEXT NOT NULL,
  asset           TEXT NOT NULL,
  principal_id    TEXT NOT NULL,
  policy_revision TEXT NOT NULL,
  amount_atomic   TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  PRIMARY KEY (reservation_id, asset),
  UNIQUE (intent_id, asset)
);

CREATE TABLE IF NOT EXISTS broadcasts (
  key          TEXT PRIMARY KEY,
  sender_key   TEXT NOT NULL,
  sender_nonce INTEGER NOT NULL,
  terms        TEXT NOT NULL,
  tx_hash      TEXT,
  created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sender_nonces (
  sender_key TEXT PRIMARY KEY,
  next_nonce INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
  seq        INTEGER PRIMARY KEY,
  event      TEXT NOT NULL,
  event_hash TEXT NOT NULL UNIQUE,
  prev_hash  TEXT NOT NULL,
  intent_id  TEXT
);
CREATE INDEX IF NOT EXISTS audit_events_intent ON audit_events (intent_id, seq);
`;

/** Parses a stored or supplied atomic amount, refusing anything but a uint256 integer. */
export function parseAtomic(value: string, where: string): bigint {
  if (!/^(0|[1-9][0-9]{0,77})$/.test(value)) {
    throw new Error(`${where}: ${value} is not a base-10 atomic integer amount`);
  }
  const parsed = BigInt(value);
  if (parsed > MAX_UINT256) throw new Error(`${where}: ${value} exceeds uint256`);
  return parsed;
}

const MAX_UINT256 = (1n << 256n) - 1n;

type PreparedLegs = readonly {
  readonly asset: string;
  readonly amount: bigint;
  readonly perPayment: bigint;
  readonly total: bigint;
}[];

/** Validates and normalizes reservation legs before any transaction is opened. */
function prepareLegs(request: BudgetReservationRequest): PreparedLegs {
  if (request.legs.length === 0) {
    throw new Error("a reservation requires at least one leg");
  }
  const prepared = request.legs.map((leg) => ({
    asset: normalizeAsset(leg.asset),
    amount: parseAtomic(leg.amountAtomic, `reservation leg ${leg.asset} amountAtomic`),
    perPayment: parseAtomic(leg.maxAmountPerPayment, `reservation leg ${leg.asset} maxAmountPerPayment`),
    total: parseAtomic(leg.totalBudget, `reservation leg ${leg.asset} totalBudget`),
  }));
  if (new Set(prepared.map((leg) => leg.asset)).size !== prepared.length) {
    throw new Error("reservation legs must each name a distinct budget asset");
  }
  // Sorted so the binding digest does not depend on argument order.
  return [...prepared].sort((a, b) => (a.asset < b.asset ? -1 : a.asset > b.asset ? 1 : 0));
}

function normalizeAsset(asset: string): string {
  return asset.toLowerCase();
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
