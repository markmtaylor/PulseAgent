/**
 * Operator-controlled chain profiles.
 *
 * A chain is usable only if it has a profile here. There is no inference from a
 * symbol, no wildcard network, and no fallback across chain IDs: an unknown
 * CAIP-2 id is disabled, not "probably fine".
 */

/** How a profile may be used. Nothing widens this at runtime. */
export type ChainMode =
  /** A disposable node this process tree owns, reachable only over loopback. */
  | "local-ephemeral"
  /** A public test network. */
  | "public-test"
  /** Reads only. No signing path exists for these, by construction. */
  | "read-only";

/**
 * What, if anything, may be broadcast to a chain.
 *
 * `owned-local` is the only variant this build can act on. The public-test
 * variant carries `implemented: false`: the approval verifier it would need does
 * not exist yet, so every broadcast attempt fails explicitly rather than
 * falling back to local mode or accepting a caller-supplied string.
 */
export type BroadcastSupport =
  | { readonly kind: "owned-local" }
  | { readonly kind: "operator-approval-required"; readonly implemented: false }
  | { readonly kind: "disabled" };

/** How a settlement is judged canonical on this chain. */
export type FinalityRule =
  /** Receipt block must be at or below the node's `finalized` tag and still canonical. */
  | { readonly kind: "finalized-tag" }
  /**
   * Receipt block must be at least `confirmations` deep and still canonical.
   * A documented local-rehearsal rule only; never used for a public chain.
   */
  | { readonly kind: "confirmations"; readonly confirmations: number };

export interface ChainProfile {
  readonly caip2: string;
  readonly chainId: number;
  readonly displayName: string;
  readonly mode: ChainMode;
  readonly broadcast: BroadcastSupport;
  /**
   * Exact RPC origins permitted, as `URL.origin` renders them (so a non-default
   * port is part of the value). Empty for `local-ephemeral`, whose port is not
   * known until the owned node is started; those origins are supplied per call.
   */
  readonly allowedRpcOrigins: readonly string[];
  /** The RPC host must be a loopback literal. Set for owned ephemeral nodes. */
  readonly requireLoopbackRpc: boolean;
  readonly finality: FinalityRule;
  /**
   * EVM target fixture bytecode must be compiled for. Both PulseChain networks
   * reject MCOPY and TSTORE at the observed finalized blocks, so Cancun-only
   * opcodes must not appear in anything we deploy or etch.
   */
  readonly evmTarget: "shanghai";
  /** Native gas currency symbol, for operator-facing output only. */
  readonly nativeSymbol: string;
  /** Date the capability evidence behind this profile was collected (UTC date). */
  readonly evidenceDate: string;
  readonly notes: string;
}

const PROFILES: readonly ChainProfile[] = [
  {
    caip2: "eip155:31337",
    chainId: 31337,
    displayName: "Local ephemeral EVM (disposable)",
    mode: "local-ephemeral",
    broadcast: { kind: "owned-local" },
    allowedRpcOrigins: [],
    requireLoopbackRpc: true,
    finality: { kind: "confirmations", confirmations: 1 },
    evmTarget: "shanghai",
    nativeSymbol: "ETH(test)",
    evidenceDate: "2026-11-01",
    notes:
      "Chain ID 31337 is not authorization on its own: the RPC must be a loopback literal and its " +
      "exact origin must be one this process tree started and passed in. Single-confirmation " +
      "finality is a documented local rehearsal rule, unacceptable for any public chain.",
  },
  {
    caip2: "eip155:943",
    chainId: 943,
    displayName: "PulseChain v4 testnet",
    mode: "public-test",
    broadcast: { kind: "operator-approval-required", implemented: false },
    allowedRpcOrigins: ["https://rpc.v4.testnet.pulsechain.com"],
    requireLoopbackRpc: false,
    finality: { kind: "finalized-tag" },
    evmTarget: "shanghai",
    nativeSymbol: "tPLS",
    evidenceDate: "2026-11-01",
    notes:
      "Read-only probes succeeded over verified TLS. No transaction has been signed or submitted. " +
      "MCOPY and TSTORE return invalid opcode at the observed finalized block, and the canonical " +
      "x402 exact Permit2 proxy's settlement path reverts on MCOPY there, so EIP-3009 is the only " +
      "candidate asset transfer method. No test asset is approved and no broadcast path exists.",
  },
  {
    caip2: "eip155:369",
    chainId: 369,
    displayName: "PulseChain mainnet",
    mode: "read-only",
    broadcast: { kind: "disabled" },
    allowedRpcOrigins: ["https://rpc.pulsechain.com"],
    requireLoopbackRpc: false,
    finality: { kind: "finalized-tag" },
    evmTarget: "shanghai",
    nativeSymbol: "PLS",
    evidenceDate: "2026-11-01",
    notes:
      "Read-only in this build. Mainnet signing and deployment are not implemented and there is no " +
      "configuration that enables them.",
  },
];

const BY_CAIP2 = new Map(PROFILES.map((p) => [p.caip2, p]));

/** Every configured profile, for operator-facing listings. */
export function listChainProfiles(): readonly ChainProfile[] {
  return PROFILES;
}

/** The profile for a CAIP-2 id, or undefined when the chain is not configured. */
export function findChainProfile(caip2: string): ChainProfile | undefined {
  return BY_CAIP2.get(caip2);
}

/** The profile for a CAIP-2 id. Throws for an unconfigured chain. */
export function requireChainProfile(caip2: string): ChainProfile {
  const profile = BY_CAIP2.get(caip2);
  if (!profile) throw new ChainNotConfiguredError(caip2);
  return profile;
}

export class ChainNotConfiguredError extends Error {
  readonly caip2: string;

  constructor(caip2: string) {
    super(`chain ${caip2} has no configured profile; unknown chains are disabled`);
    this.name = "ChainNotConfiguredError";
    this.caip2 = caip2;
  }
}

export class ChainPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ChainPolicyError";
  }
}

/** Raised where a public-chain broadcast is requested but no approval verifier exists. */
export class PublicBroadcastNotImplementedError extends Error {
  readonly caip2: string;

  constructor(caip2: string) {
    super(
      `broadcasting to ${caip2} requires a verified operator approval record; that verifier is not ` +
        `implemented in this build, so the request fails instead of running in local mode`,
    );
    this.name = "PublicBroadcastNotImplementedError";
    this.caip2 = caip2;
  }
}

/** `eip155:<id>` for a numeric EVM chain ID. */
export function caip2ForChainId(chainId: number): string {
  if (!Number.isSafeInteger(chainId) || chainId <= 0) {
    throw new ChainPolicyError(`invalid EVM chain id ${String(chainId)}`);
  }
  return `eip155:${chainId}`;
}

/** The numeric EVM chain ID in an `eip155:*` CAIP-2 id. */
export function chainIdForCaip2(caip2: string): number {
  const match = /^eip155:(\d{1,10})$/.exec(caip2);
  if (!match?.[1]) throw new ChainPolicyError(`not an eip155 CAIP-2 chain id: ${caip2}`);
  const chainId = Number(match[1]);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) {
    throw new ChainPolicyError(`invalid EVM chain id in ${caip2}`);
  }
  return chainId;
}

export interface RpcAllowOptions {
  /**
   * Exact origins of loopback nodes this process tree started, e.g.
   * `http://127.0.0.1:49721`. Required for a `local-ephemeral` profile, whose
   * ephemeral port cannot be known at configuration time. Ignored otherwise.
   */
  readonly ownedLocalOrigins?: readonly string[];
}

/**
 * Rejects an RPC endpoint the profile does not allow.
 *
 * Comparison is on the exact `URL.origin`, so scheme, host and port must all
 * match — an approved host on an unapproved port is refused. A `local-ephemeral`
 * profile additionally requires a loopback host literal and an origin the caller
 * proves it owns; a hostname that merely resolves to loopback is not accepted,
 * since DNS is not ours to trust. HTTP-level redirects are a separate concern,
 * handled where requests are actually issued.
 *
 * @param profile Chain profile to check against.
 * @param rpcUrl Candidate endpoint.
 * @param options Owned loopback origins, for local profiles.
 * @returns The parsed URL when allowed.
 */
export function assertRpcAllowed(profile: ChainProfile, rpcUrl: string, options: RpcAllowOptions = {}): URL {
  let url: URL;
  try {
    url = new URL(rpcUrl);
  } catch {
    throw new ChainPolicyError(`RPC url is not a valid URL for ${profile.caip2}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ChainPolicyError(`RPC scheme ${url.protocol} is not allowed for ${profile.caip2}`);
  }
  if (url.username !== "" || url.password !== "") {
    throw new ChainPolicyError(`RPC url for ${profile.caip2} must not embed credentials`);
  }
  if (url.search !== "" || url.hash !== "") {
    throw new ChainPolicyError(`RPC url for ${profile.caip2} must not carry a query or fragment`);
  }
  if (url.pathname !== "/" && url.pathname !== "") {
    throw new ChainPolicyError(`RPC url for ${profile.caip2} must not carry a path`);
  }

  if (profile.mode === "local-ephemeral") {
    if (!isLoopbackHost(url.hostname)) {
      throw new ChainPolicyError(
        `${profile.caip2} requires a loopback RPC host; ${url.hostname} is not a loopback literal`,
      );
    }
    const owned = options.ownedLocalOrigins ?? [];
    if (owned.length === 0) {
      throw new ChainPolicyError(
        `${profile.caip2} requires the origin of a node this process tree started; none was supplied`,
      );
    }
    if (!owned.includes(url.origin)) {
      throw new ChainPolicyError(
        `RPC origin ${url.origin} is not an owned ephemeral node started by this process tree`,
      );
    }
    return url;
  }

  if (profile.requireLoopbackRpc && !isLoopbackHost(url.hostname)) {
    throw new ChainPolicyError(
      `${profile.caip2} requires a loopback RPC host; ${url.hostname} is not a loopback literal`,
    );
  }
  if (!profile.allowedRpcOrigins.includes(url.origin)) {
    throw new ChainPolicyError(`RPC origin ${url.origin} is not in the allowlist for ${profile.caip2}`);
  }
  return url;
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1";
}

/**
 * Rejects a node whose self-reported chain ID is not the profile's.
 * Called at startup and again before any signing decision.
 */
export function assertChainIdMatches(profile: ChainProfile, observedChainId: number): void {
  if (observedChainId !== profile.chainId) {
    throw new ChainPolicyError(
      `RPC reports chain id ${String(observedChainId)} but profile ${profile.caip2} expects ${String(profile.chainId)}`,
    );
  }
}

/**
 * Rejects a broadcast the profile does not permit.
 *
 * Only an owned local chain passes. A read-only chain has no approval that
 * unlocks it, and a public test chain fails with
 * {@link PublicBroadcastNotImplementedError} because this build has no verifier
 * for an operator approval record. A caller-supplied approval string is never
 * sufficient and is deliberately not a parameter here.
 */
export function assertBroadcastAllowed(profile: ChainProfile): void {
  switch (profile.broadcast.kind) {
    case "owned-local":
      return;
    case "operator-approval-required":
      throw new PublicBroadcastNotImplementedError(profile.caip2);
    case "disabled":
      throw new ChainPolicyError(
        `${profile.caip2} (${profile.displayName}) is read-only in this build; no transaction may be broadcast`,
      );
    default: {
      const exhaustive: never = profile.broadcast;
      throw new ChainPolicyError(`unhandled broadcast support ${JSON.stringify(exhaustive)}`);
    }
  }
}
