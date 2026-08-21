import { describe, expect, it } from "vitest";
import {
  DEFAULT_NETWORK,
  NETWORKS,
  allowedRpcOrigin,
  buildCustomNetworkConfig,
  validateCustomNetworkInput,
  type CustomNetworkFormInput,
  type NetworkId,
} from "./networks";

/**
 * These tests exist to prove the actual substance of "switching networks
 * changes which RPC/API endpoints get used": that every network's config
 * entry is genuinely distinct (not one network's values duplicated under a
 * second name), and that each network's own default RPC URL is exactly
 * what `allowedRpcOrigin` — the CSP/origin gate every RPC call goes through
 * — allows for that network. `switchNetwork` itself (in main.ts) is DOM-
 * manipulating glue code around this table; this is the part of "network
 * switching" that's actually meaningful to unit test in isolation.
 */

/**
 * Expected chain ID per network, exactly as verified before use (see each
 * entry's own doc comment in networks.ts for the verification source —
 * chainlist.org for BNB Smart Chain mainnet/Arbitrum/Base, or the user's
 * direct confirmation for BNB Smart Chain Testnet).
 */
const EXPECTED_CHAIN_IDS: Record<NetworkId, number> = {
  sepolia: 11155111,
  mainnet: 1,
  bsc: 56,
  bscTestnet: 97,
  arbitrum: 42161,
  arbitrumSepolia: 421614,
  base: 8453,
  baseSepolia: 84532,
  polygon: 137,
  optimism: 10,
  polygonAmoy: 80002,
  optimismSepolia: 11155420,
};

const ALL_NETWORK_IDS = Object.keys(NETWORKS) as NetworkId[];

describe("network configuration", () => {
  it("defaults to Ethereum Mainnet, not a testnet", () => {
    // The selector shows mainnets only (no testnet toggle) -- a testnet
    // default would be permanently hidden from its own selector, the exact
    // "blank page" bug this app already shipped and fixed once. See
    // DEFAULT_NETWORK's own doc comment.
    expect(DEFAULT_NETWORK).toBe("mainnet");
    expect(NETWORKS[DEFAULT_NETWORK].isTestnet).toBe(false);
  });

  it("has exactly the twelve expected networks, each with its verified chain ID", () => {
    expect(ALL_NETWORK_IDS.sort()).toEqual(Object.keys(EXPECTED_CHAIN_IDS).sort());
    for (const id of ALL_NETWORK_IDS) {
      expect(NETWORKS[id].chainId).toBe(EXPECTED_CHAIN_IDS[id]);
    }
  });

  it("gives every network a chain ID no other network shares", () => {
    const chainIds = ALL_NETWORK_IDS.map((id) => NETWORKS[id].chainId);
    expect(new Set(chainIds).size).toBe(chainIds.length);
  });

  it("gives every network its own default RPC URL, shared with no other network", () => {
    const rpcUrls = ALL_NETWORK_IDS.map((id) => NETWORKS[id].defaultRpcUrl);
    expect(new Set(rpcUrls).size).toBe(rpcUrls.length);
  });

  it("gives every network its own explorer base URL, shared with no other network", () => {
    const explorerUrls = ALL_NETWORK_IDS.map((id) => NETWORKS[id].explorerBaseUrl);
    expect(new Set(explorerUrls).size).toBe(explorerUrls.length);
    // Spot-check the actual verified subdomains for the four networks added
    // 2026-08-27, not just "all different from each other".
    expect(NETWORKS.bsc.explorerBaseUrl).toBe("https://bscscan.com");
    expect(NETWORKS.bscTestnet.explorerBaseUrl).toBe("https://testnet.bscscan.com");
    expect(NETWORKS.arbitrum.explorerBaseUrl).toBe("https://arbiscan.io");
    expect(NETWORKS.arbitrumSepolia.explorerBaseUrl).toBe("https://sepolia.arbiscan.io");
    expect(NETWORKS.base.explorerBaseUrl).toBe("https://basescan.org");
    expect(NETWORKS.baseSepolia.explorerBaseUrl).toBe("https://sepolia.basescan.org");
    expect(NETWORKS.polygon.explorerBaseUrl).toBe("https://polygonscan.com");
    expect(NETWORKS.optimism.explorerBaseUrl).toBe("https://optimistic.etherscan.io");
    expect(NETWORKS.polygonAmoy.explorerBaseUrl).toBe("https://amoy.polygonscan.com");
    expect(NETWORKS.optimismSepolia.explorerBaseUrl).toBe("https://sepolia-optimistic.etherscan.io");
  });

  it("only allows each network's own RPC origin for that network, never another's", () => {
    const origins = ALL_NETWORK_IDS.map((id) => allowedRpcOrigin(NETWORKS[id]));
    // The actual property that matters for the "never confused about which
    // network I'm talking to" requirement: no two networks may share an
    // allowed origin.
    expect(new Set(origins).size).toBe(origins.length);
    for (const id of ALL_NETWORK_IDS) {
      expect(allowedRpcOrigin(NETWORKS[id])).toBe(new URL(NETWORKS[id].defaultRpcUrl).origin);
    }
  });

  it("marks every testnet sendable and every mainnet read-only", () => {
    for (const id of ALL_NETWORK_IDS) {
      const network = NETWORKS[id];
      expect(network.sendSupported).toBe(network.isTestnet);
    }
    // Concrete enumeration, not just the derived rule above -- pins down
    // exactly which four are which, so a typo'd `isTestnet` on one entry
    // can't silently pass by coincidentally matching its own sendSupported
    // value. This correlation is a property of today's built-in networks,
    // not a rule the code enforces -- see NetworkConfig.isTestnet's own
    // doc comment on why the two fields are deliberately independent.
    for (const id of [
      "sepolia",
      "bscTestnet",
      "arbitrumSepolia",
      "baseSepolia",
      "polygonAmoy",
      "optimismSepolia",
    ] as const) {
      expect(NETWORKS[id].isTestnet).toBe(true);
      expect(NETWORKS[id].sendSupported).toBe(true);
    }
    for (const id of ["mainnet", "bsc", "arbitrum", "base", "polygon", "optimism"] as const) {
      expect(NETWORKS[id].isTestnet).toBe(false);
      expect(NETWORKS[id].sendSupported).toBe(false);
    }
  });

  it("marks every built-in network as not custom", () => {
    for (const id of ALL_NETWORK_IDS) {
      expect(NETWORKS[id].isCustom).toBe(false);
    }
  });

  it("gives each network its own native-currency symbol", () => {
    expect(NETWORKS.bsc.nativeCurrencySymbol).toBe("BNB");
    expect(NETWORKS.bscTestnet.nativeCurrencySymbol).toBe("BNB");
    // Polygon's native currency is POL, not MATIC -- rebranded on Polygon
    // PoS in 2024. Matches viem's own `polygon.nativeCurrency` and
    // chainlist.org's current listing, cross-checked at verification time.
    expect(NETWORKS.polygon.nativeCurrencySymbol).toBe("POL");
    expect(NETWORKS.polygonAmoy.nativeCurrencySymbol).toBe("POL");
    for (const id of [
      "sepolia",
      "mainnet",
      "arbitrum",
      "arbitrumSepolia",
      "base",
      "baseSepolia",
      "optimism",
      "optimismSepolia",
    ] as const) {
      expect(NETWORKS[id].nativeCurrencySymbol).toBe("ETH");
    }
  });

  it("gives each network its own, separately-verified token list, never reused across networks", () => {
    const seenAddresses = new Set<string>();
    for (const id of ALL_NETWORK_IDS) {
      for (const token of NETWORKS[id].tokens) {
        const address = token.address.toLowerCase();
        expect(seenAddresses.has(address)).toBe(false);
        seenAddresses.add(address);
      }
    }
  });

  it("has no token list yet for the networks added after the original Sepolia/mainnet pair (deliberately out of scope for those steps)", () => {
    for (const id of [
      "bsc",
      "bscTestnet",
      "arbitrum",
      "arbitrumSepolia",
      "base",
      "baseSepolia",
      "polygon",
      "optimism",
      "polygonAmoy",
      "optimismSepolia",
    ] as const) {
      expect(NETWORKS[id].tokens).toEqual([]);
    }
  });
});

/** A complete, valid custom-network form submission, for tests to mutate one field at a time. */
function validInput(overrides: Partial<CustomNetworkFormInput> = {}): CustomNetworkFormInput {
  return {
    label: "My Devnet",
    rpcUrl: "https://devnet.example.com/rpc",
    chainIdInput: "1337",
    nativeCurrencySymbol: "DEV",
    explorerBaseUrlInput: "",
    ...overrides,
  };
}

const BUILT_IN_NETWORKS = Object.values(NETWORKS);

describe("validateCustomNetworkInput", () => {
  it("accepts well-formed input with no explorer URL", () => {
    const result = validateCustomNetworkInput(validInput(), BUILT_IN_NETWORKS);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toEqual({
        label: "My Devnet",
        rpcUrl: "https://devnet.example.com/rpc",
        chainId: 1337,
        nativeCurrencySymbol: "DEV",
        explorerBaseUrl: null,
      });
    }
  });

  it("accepts well-formed input with an explorer URL, and strips a trailing slash", () => {
    const result = validateCustomNetworkInput(
      validInput({ explorerBaseUrlInput: "https://explorer.example.com/" }),
      BUILT_IN_NETWORKS,
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.explorerBaseUrl).toBe("https://explorer.example.com");
    }
  });

  it("trims whitespace from every field", () => {
    const result = validateCustomNetworkInput(
      validInput({ label: "  My Devnet  ", rpcUrl: "  https://devnet.example.com/rpc  ", chainIdInput: " 1337 " }),
      BUILT_IN_NETWORKS,
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.label).toBe("My Devnet");
      expect(result.value.rpcUrl).toBe("https://devnet.example.com/rpc");
    }
  });

  it("rejects an empty network name", () => {
    const result = validateCustomNetworkInput(validInput({ label: "  " }), BUILT_IN_NETWORKS);
    expect(result.ok).toBe(false);
  });

  it("rejects a malformed RPC URL", () => {
    for (const rpcUrl of ["not a url", "ftp://devnet.example.com", ""]) {
      const result = validateCustomNetworkInput(validInput({ rpcUrl }), BUILT_IN_NETWORKS);
      expect(result.ok, `expected ${JSON.stringify(rpcUrl)} to be rejected`).toBe(false);
    }
  });

  it("rejects a chain ID that isn't a plain non-negative integer", () => {
    // The exact classic-bug shapes a naive Number() coercion would let
    // through: scientific notation, hex, decimals, signs.
    for (const chainIdInput of ["1e3", "0x1", "1.5", "-1", "+1", "abc", "", "13 37"]) {
      const result = validateCustomNetworkInput(validInput({ chainIdInput }), BUILT_IN_NETWORKS);
      expect(result.ok, `expected chain id ${JSON.stringify(chainIdInput)} to be rejected`).toBe(false);
    }
  });

  it("rejects a zero chain ID", () => {
    const result = validateCustomNetworkInput(validInput({ chainIdInput: "0" }), BUILT_IN_NETWORKS);
    expect(result.ok).toBe(false);
  });

  it("rejects an empty native currency symbol", () => {
    const result = validateCustomNetworkInput(validInput({ nativeCurrencySymbol: "  " }), BUILT_IN_NETWORKS);
    expect(result.ok).toBe(false);
  });

  it("rejects a malformed explorer URL, but allows an empty one", () => {
    const malformed = validateCustomNetworkInput(
      validInput({ explorerBaseUrlInput: "not a url" }),
      BUILT_IN_NETWORKS,
    );
    expect(malformed.ok).toBe(false);

    const empty = validateCustomNetworkInput(validInput({ explorerBaseUrlInput: "" }), BUILT_IN_NETWORKS);
    expect(empty.ok).toBe(true);
  });

  it("rejects a chain ID that collides with an existing network", () => {
    const result = validateCustomNetworkInput(
      validInput({ chainIdInput: String(NETWORKS.sepolia.chainId) }),
      BUILT_IN_NETWORKS,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("Sepolia Testnet");
    }
  });
});

describe("buildCustomNetworkConfig", () => {
  it("builds a NetworkConfig with the expected fixed fields", () => {
    const result = validateCustomNetworkInput(validInput(), BUILT_IN_NETWORKS);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const network = buildCustomNetworkConfig("custom-1", result.value);

    expect(network.id).toBe("custom-1");
    expect(network.label).toBe("My Devnet");
    expect(network.chainId).toBe(1337);
    expect(network.nativeCurrencySymbol).toBe("DEV");
    expect(network.viemChain.id).toBe(1337);
    // The properties that make this feature's design deliberate, not
    // incidental -- see NetworkConfig.isCustom/isTestnet/sendSupported's
    // own doc comments for why each of these three is set the way it is.
    expect(network.isCustom).toBe(true);
    expect(network.isTestnet).toBe(false);
    expect(network.sendSupported).toBe(true);
    expect(network.tokens).toEqual([]);
    expect(network.explorerBaseUrl).toBe("");
  });

  it("uses the provided explorer URL when given", () => {
    const result = validateCustomNetworkInput(
      validInput({ explorerBaseUrlInput: "https://explorer.example.com" }),
      BUILT_IN_NETWORKS,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const network = buildCustomNetworkConfig("custom-2", result.value);
    expect(network.explorerBaseUrl).toBe("https://explorer.example.com");
  });
});
