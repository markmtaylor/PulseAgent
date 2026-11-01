import { z } from "zod";

/**
 * Wire and storage schemas. Every schema is strict: an unknown field is a
 * rejection, not something to ignore, because these objects cross trust
 * boundaries (seller -> buyer, buyer -> signer, process -> durable state).
 */

/** Lowercase-normalized 20-byte hex address. */
export const AddressSchema = z
  .string()
  .regex(/^0x[0-9a-fA-F]{40}$/, "expected a 0x-prefixed 20-byte hex address");

/** 32-byte hex, used for EIP-3009 nonces and block/transaction hashes. */
export const Bytes32Schema = z
  .string()
  .regex(/^0x[0-9a-fA-F]{64}$/, "expected 0x-prefixed 32-byte hex");

/**
 * An atomic token amount: a base-10 integer string with no sign, no decimal
 * point, no exponent and no leading zeroes. Floats never represent money here,
 * and "1e6", "1.0", "-1" and "0x01" are all rejected.
 */
export const AtomicAmountSchema = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,77})$/, "expected a base-10 atomic integer amount");

/** CAIP-2 chain id restricted to the EVM namespace. */
export const Caip2Schema = z.string().regex(/^eip155:\d{1,10}$/, "expected an eip155 CAIP-2 chain id");

/** A `sha256:<64 hex>` digest produced by this codebase. */
export const DigestSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/, "expected a sha256:<hex> digest");

/** Unix seconds. Bounded so an absurd expiry cannot be smuggled through. */
export const UnixSecondsSchema = z.number().int().min(0).max(4_000_000_000);

/** An origin with no path, query or fragment, used to pin a service's identity. */
export const ServiceOriginSchema = z
  .string()
  .regex(/^https?:\/\/[^/?#\s]+$/, "expected a bare http(s) origin with no path");

/**
 * The asset an operator has approved for payments.
 *
 * `eip712Name` / `eip712Version` are the token's own EIP-712 domain fields. They
 * are configuration, not something read from a quote, so a seller cannot steer
 * a signature onto a different domain.
 */
export const AssetProfileSchema = z.strictObject({
  address: AddressSchema,
  symbol: z.string().min(1).max(32),
  decimals: z.number().int().min(0).max(36),
  eip712Name: z.string().min(1).max(128),
  eip712Version: z.string().min(1).max(32),
  /** Asset transfer method of the x402 exact scheme. Only EIP-3009 is implemented. */
  assetTransferMethod: z.literal("eip3009"),
  /** Set when the asset is a valueless local fixture, so output can say so. */
  valuelessTestFixture: z.boolean(),
});
export type AssetProfile = z.infer<typeof AssetProfileSchema>;

/**
 * An operator-authored spending policy. The buyer process and the signer each
 * load this independently; the signer's copy is authoritative.
 */
export const PaymentPolicySchema = z.strictObject({
  /** Identity of the principal the signer acts for. */
  principalId: z.string().min(1).max(128),
  /** Opaque revision recorded in every intent and audit event. */
  policyRevision: z.string().min(1).max(128),
  network: Caip2Schema,
  /** Exact service origins this policy may pay. */
  allowedServiceOrigins: z.array(ServiceOriginSchema).min(1).max(32),
  /** Exact resource paths allowed on those origins. */
  allowedResourcePaths: z.array(z.string().regex(/^\/[^\s?#]{0,256}$/)).min(1).max(64),
  /** Payee addresses allowed to receive a payment. */
  allowedPayees: z.array(AddressSchema).min(1).max(32),
  /** Assets allowed, keyed by address at load time. */
  allowedAssets: z.array(AssetProfileSchema).min(1).max(16),
  /** Hard per-payment ceiling in atomic units of the quoted asset. */
  maxAmountPerPayment: AtomicAmountSchema,
  /** Lifetime ceiling across all payments under this policy, atomic units. */
  totalBudget: AtomicAmountSchema,
  /**
   * Worst-case native gas reserved per payment, in wei. Gas is a separate
   * bounded resource from the token amount, so it has its own ceiling.
   */
  maxGasReservationWei: AtomicAmountSchema,
  /** Lifetime ceiling on sponsored native gas under this policy, in wei. */
  totalGasBudgetWei: AtomicAmountSchema,
  /** Longest quote validity the buyer will accept, in seconds. */
  maxQuoteTtlSeconds: z.number().int().min(1).max(3600),
  /** Longest request body the buyer will submit, in bytes. */
  maxRequestBodyBytes: z.number().int().min(1).max(65_536),
  /** Operator approval record id. Required before any public-chain broadcast. */
  operatorApprovalId: z.string().min(1).max(128).optional(),
});
export type PaymentPolicy = z.infer<typeof PaymentPolicySchema>;

/**
 * A seller's quote, normalized. This is the only shape the policy engine
 * accepts; the raw 402 response is mapped onto it first and anything that does
 * not map is a rejection.
 */
export const NormalizedQuoteSchema = z.strictObject({
  quoteId: z.string().min(8).max(128),
  serviceOrigin: ServiceOriginSchema,
  resourcePath: z.string().regex(/^\/[^\s?#]{0,256}$/),
  /** Digest of the exact request body this quote prices. */
  requestDigest: DigestSchema,
  network: Caip2Schema,
  asset: AddressSchema,
  assetDecimals: z.number().int().min(0).max(36),
  payTo: AddressSchema,
  amount: AtomicAmountSchema,
  expiresAt: UnixSecondsSchema,
  /** EIP-712 domain name the seller claims for the asset. Cross-checked, never trusted. */
  eip712Name: z.string().min(1).max(128),
  eip712Version: z.string().min(1).max(32),
  assetTransferMethod: z.literal("eip3009"),
  maxTimeoutSeconds: z.number().int().min(1).max(3600),
});
export type NormalizedQuote = z.infer<typeof NormalizedQuoteSchema>;

/** Lifecycle of one payment intent. */
export const IntentStateSchema = z.enum([
  "QUOTED",
  "POLICY_APPROVED",
  "RESERVED",
  "AUTHORIZED",
  "SUBMITTED",
  "INCLUDED",
  "FINALIZED",
  "DELIVERED",
  "DENIED",
  "EXPIRED",
  "REVERTED",
  "RECONCILING",
]);
export type IntentState = z.infer<typeof IntentStateSchema>;

/** States no further transition may leave. */
export const TERMINAL_STATES: readonly IntentState[] = ["DELIVERED", "DENIED", "EXPIRED", "REVERTED"];

/**
 * The immutable record of a payment intent. Written durably before any external
 * side effect, and never rewritten except to advance `state` and attach
 * settlement facts.
 */
export const PaymentIntentSchema = z.strictObject({
  intentId: z.string().min(8).max(128),
  /** Caller-supplied key that makes a retry the same payment, not a new one. */
  idempotencyKey: z.string().min(8).max(128),
  principalId: z.string().min(1).max(128),
  policyRevision: z.string().min(1).max(128),
  quote: NormalizedQuoteSchema,
  createdAt: UnixSecondsSchema,
  state: IntentStateSchema,
  /** Operator approval record id, when the chain requires one. */
  operatorApprovalId: z.string().min(1).max(128).optional(),
  /** Signer reservation id held against the budget. */
  reservationId: z.string().min(8).max(128).optional(),
  /** EIP-3009 authorization nonce, once the signer has issued one. */
  authorizationNonce: Bytes32Schema.optional(),
  /** Digest of the signature. The signature itself is never persisted or logged. */
  authorizationSignatureDigest: DigestSchema.optional(),
  /** Settlement transaction hash as reported by the facilitator. */
  settlementTxHash: Bytes32Schema.optional(),
  /** Independently verified settlement facts. */
  settlement: z
    .strictObject({
      chainId: z.number().int().positive(),
      txHash: Bytes32Schema,
      blockNumber: AtomicAmountSchema,
      blockHash: Bytes32Schema,
      asset: AddressSchema,
      from: AddressSchema,
      to: AddressSchema,
      amount: AtomicAmountSchema,
      gasUsed: AtomicAmountSchema,
      effectiveGasPriceWei: AtomicAmountSchema,
      finality: z.enum(["confirmations", "finalized-tag"]),
      confirmations: AtomicAmountSchema,
      verifiedAt: UnixSecondsSchema,
    })
    .optional(),
  /** Digest of the delivered result, for the buyer's independent check. */
  resultDigest: DigestSchema.optional(),
  /** Why a terminal non-success state was reached. Never carries upstream detail verbatim. */
  terminalReason: z.string().min(1).max(256).optional(),
});
export type PaymentIntent = z.infer<typeof PaymentIntentSchema>;

/**
 * What the buyer asks the isolated signer to authorize.
 *
 * The signer re-derives everything it needs from these fields and its own
 * policy copy. There is no "approved: true" field, because a model-side flag
 * would carry no authority.
 */
export const SignerAuthorizationRequestSchema = z.strictObject({
  intentId: z.string().min(8).max(128),
  idempotencyKey: z.string().min(8).max(128),
  principalId: z.string().min(1).max(128),
  quote: NormalizedQuoteSchema,
  /** Typed-data request the signer must independently reconstruct and compare. */
  typedData: z.strictObject({
    primaryType: z.literal("TransferWithAuthorization"),
    domain: z.strictObject({
      name: z.string().min(1).max(128),
      version: z.string().min(1).max(32),
      chainId: z.number().int().positive(),
      verifyingContract: AddressSchema,
    }),
    message: z.strictObject({
      from: AddressSchema,
      to: AddressSchema,
      value: AtomicAmountSchema,
      validAfter: AtomicAmountSchema,
      validBefore: AtomicAmountSchema,
      nonce: Bytes32Schema,
    }),
  }),
  /** Operator approval id, forwarded for public chains. Absent for local mode. */
  operatorApprovalId: z.string().min(1).max(128).optional(),
});
export type SignerAuthorizationRequest = z.infer<typeof SignerAuthorizationRequestSchema>;

export const SignerAuthorizationResponseSchema = z.strictObject({
  intentId: z.string().min(8).max(128),
  reservationId: z.string().min(8).max(128),
  signature: z.string().regex(/^0x[0-9a-fA-F]{130}$/),
  signatureDigest: DigestSchema,
  payer: AddressSchema,
  policyRevision: z.string().min(1).max(128),
});
export type SignerAuthorizationResponse = z.infer<typeof SignerAuthorizationResponseSchema>;

/** Append-only audit record. `payload` is redacted before it reaches here. */
export const AuditEventSchema = z.strictObject({
  schemaVersion: z.literal(1),
  seq: z.number().int().min(1),
  /** RFC 3339 UTC timestamp. */
  at: z.string().min(20).max(32),
  actor: z.enum(["buyer", "signer", "facilitator", "seller", "verifier", "operator"]),
  kind: z.string().min(1).max(64),
  intentId: z.string().min(8).max(128).optional(),
  policyRevision: z.string().min(1).max(128).optional(),
  operatorApprovalId: z.string().min(1).max(128).optional(),
  state: IntentStateSchema.optional(),
  payload: z.record(z.string(), z.unknown()),
  /** Event hash of the previous record, or the genesis constant for seq 1. */
  prevHash: DigestSchema,
  /** Digest over this record with `eventHash` omitted. */
  eventHash: DigestSchema,
});
export type AuditEvent = z.infer<typeof AuditEventSchema>;

/** The deterministic service this milestone demonstrates. */
export const DigestServiceRequestSchema = z.strictObject({
  /** Bounded UTF-8 input whose SHA-256 the seller computes. */
  input: z.string().min(1).max(4096),
});
export type DigestServiceRequest = z.infer<typeof DigestServiceRequestSchema>;

export const DigestServiceResultSchema = z.strictObject({
  service: z.literal("sha256-digest"),
  deterministic: z.literal(true),
  inputDigest: DigestSchema,
  outputDigest: DigestSchema,
  /** SHA-256 of the input, which is the service's actual product. */
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
});
export type DigestServiceResult = z.infer<typeof DigestServiceResultSchema>;
