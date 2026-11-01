import { describe, expect, it } from "vitest";
import {
  ChainPolicyError,
  PublicBroadcastNotImplementedError,
  assertBroadcastAllowed,
  assertChainIdMatches,
  assertRpcAllowed,
  caip2ForChainId,
  chainIdForCaip2,
  findChainProfile,
  listChainProfiles,
  requireChainProfile,
} from "@pulseagent/core";

describe("chain isolation", () => {
  it("disables a chain with no profile rather than guessing", () => {
    expect(findChainProfile("eip155:1")).toBeUndefined();
    expect(findChainProfile("eip155:8453")).toBeUndefined();
    expect(() => requireChainProfile("eip155:1")).toThrow(/no configured profile/);
    expect(() => requireChainProfile("solana:mainnet")).toThrow(/no configured profile/);
  });

  it("refuses mainnet broadcasts with no configuration that enables them", () => {
    const mainnet = requireChainProfile("eip155:369");
    expect(mainnet.mode).toBe("read-only");
    expect(mainnet.broadcast.kind).toBe("disabled");
    expect(() => assertBroadcastAllowed(mainnet)).toThrow(ChainPolicyError);
    expect(() => assertBroadcastAllowed(mainnet)).toThrow(/read-only in this build/);
  });

  it("fails explicitly on a public test chain instead of falling back", () => {
    const testnet = requireChainProfile("eip155:943");
    expect(() => assertBroadcastAllowed(testnet)).toThrow(PublicBroadcastNotImplementedError);
    // The failure must name the missing control, not merely refuse.
    expect(() => assertBroadcastAllowed(testnet)).toThrow(/operator approval record/);
  });

  it("permits broadcasting only to an owned local chain", () => {
    expect(() => assertBroadcastAllowed(requireChainProfile("eip155:31337"))).not.toThrow();
  });

  it("compares the whole origin, so an approved host on another port is refused", () => {
    const testnet = requireChainProfile("eip155:943");
    expect(() => assertRpcAllowed(testnet, "https://rpc.v4.testnet.pulsechain.com")).not.toThrow();
    // Same host, unapproved port. This is the defect that port-less comparison hid.
    expect(() => assertRpcAllowed(testnet, "https://rpc.v4.testnet.pulsechain.com:8545")).toThrow(/not in the allowlist/);
    expect(() => assertRpcAllowed(testnet, "http://rpc.v4.testnet.pulsechain.com")).toThrow(/not in the allowlist/);
    expect(() => assertRpcAllowed(testnet, "https://rpc.v4.testnet.pulsechain.com.attacker.example")).toThrow(
      /not in the allowlist/,
    );
  });

  it("refuses credentials, paths and queries in an RPC url", () => {
    const testnet = requireChainProfile("eip155:943");
    expect(() => assertRpcAllowed(testnet, "https://user:pass@rpc.v4.testnet.pulsechain.com")).toThrow(/credentials/);
    expect(() => assertRpcAllowed(testnet, "https://rpc.v4.testnet.pulsechain.com/path")).toThrow(/path/);
    expect(() => assertRpcAllowed(testnet, "https://rpc.v4.testnet.pulsechain.com/?key=x")).toThrow(/query/);
    expect(() => assertRpcAllowed(testnet, "ws://rpc.v4.testnet.pulsechain.com")).toThrow(/scheme/);
  });

  it("requires an owned loopback origin for the local chain", () => {
    const local = requireChainProfile("eip155:31337");
    // Chain id 31337 is not authorization on its own.
    expect(() => assertRpcAllowed(local, "http://127.0.0.1:8545")).toThrow(/owned ephemeral node|none was supplied/);
    expect(() =>
      assertRpcAllowed(local, "http://127.0.0.1:8545", { ownedLocalOrigins: ["http://127.0.0.1:9999"] }),
    ).toThrow(/not an owned ephemeral node/);
    expect(() =>
      assertRpcAllowed(local, "http://127.0.0.1:8545", { ownedLocalOrigins: ["http://127.0.0.1:8545"] }),
    ).not.toThrow();
    // A name that merely resolves to loopback is not a loopback literal.
    expect(() =>
      assertRpcAllowed(local, "http://localhost:8545", { ownedLocalOrigins: ["http://localhost:8545"] }),
    ).toThrow(/loopback literal/);
    expect(() =>
      assertRpcAllowed(local, "http://10.0.0.5:8545", { ownedLocalOrigins: ["http://10.0.0.5:8545"] }),
    ).toThrow(/loopback literal/);
  });

  it("rejects a node that reports a different chain id than the profile", () => {
    const local = requireChainProfile("eip155:31337");
    expect(() => assertChainIdMatches(local, 31_337)).not.toThrow();
    // A spoofed chain id must not be accepted just because the URL was allowed.
    expect(() => assertChainIdMatches(local, 1)).toThrow(/expects 31337/);
    expect(() => assertChainIdMatches(requireChainProfile("eip155:943"), 369)).toThrow(/expects 943/);
  });

  it("converts between CAIP-2 ids and chain ids, refusing malformed input", () => {
    expect(caip2ForChainId(943)).toBe("eip155:943");
    expect(chainIdForCaip2("eip155:943")).toBe(943);
    expect(() => chainIdForCaip2("solana:mainnet")).toThrow(/not an eip155/);
    expect(() => chainIdForCaip2("eip155:")).toThrow(/not an eip155/);
    expect(() => caip2ForChainId(0)).toThrow(/invalid EVM chain id/);
    expect(() => caip2ForChainId(-1)).toThrow(/invalid EVM chain id/);
  });

  it("holds every profile at the Shanghai opcode boundary", () => {
    // Both PulseChain networks reject MCOPY and TSTORE, so nothing we deploy may
    // be compiled past Shanghai — including the local rehearsal chain.
    for (const profile of listChainProfiles()) {
      expect(profile.evmTarget).toBe("shanghai");
    }
  });

  it("uses a documented confirmation rule locally and finalized blocks publicly", () => {
    expect(requireChainProfile("eip155:31337").finality).toEqual({ kind: "confirmations", confirmations: 1 });
    expect(requireChainProfile("eip155:943").finality).toEqual({ kind: "finalized-tag" });
    expect(requireChainProfile("eip155:369").finality).toEqual({ kind: "finalized-tag" });
  });
});
