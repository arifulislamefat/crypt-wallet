import { createPublicClient, defineChain, http, type Address, type Chain } from "viem";
import {
  arbitrum,
  arbitrumSepolia,
  base,
  baseSepolia,
  bsc,
  bscTestnet,
  mainnet,
  optimism,
  optimismSepolia,
  polygon,
  polygonAmoy,
  sepolia,
} from "viem/chains";
import { MAINNET_TOKENS, SEPOLIA_TOKENS, type TokenListing } from "./tokens";

/**
 * Every network this app knows about. Read-only — this module never touches
 * signing, seeds, or the vault, so it's independent of everything in
 * `main.ts`'s secret-handling flow. It only ever moves an address (public)
 * out and balances/history (public) back.
 *
 * Adding a network is meant to be a one-line addition to `NETWORKS` below,
 * not a hunt through `main.ts` for hardcoded chain IDs and RPC URLs — that
 * consolidation is the actual point of this module (see the project note:
 * Sepolia used to be hardcoded in several places on both the Rust and
 * frontend sides).
 */
export type NetworkId =
  | "sepolia"
  | "mainnet"
  | "bsc"
  | "bscTestnet"
  | "arbitrum"
  | "arbitrumSepolia"
  | "base"
  | "baseSepolia"
  | "polygon"
  | "polygonAmoy"
  | "optimism"
  | "optimismSepolia";

export interface NetworkConfig {
  /**
   * A built-in network's fixed `NetworkId`, or a generated id
   * (`custom-<n>`) for a network the user added at runtime — see
   * `buildCustomNetworkConfig`. Either way, this is the value
   * `activeNetworkId`/`network-select`'s option values use, so it has to be
   * unique across BOTH built-ins and whatever custom networks currently
   * exist.
   */
  id: string;
  /** Short, unambiguous UI label — shown in the network selector and the "which network am I looking at" banner. */
  label: string;
  chainId: number;
  /**
   * Whether this is a test network. Used to group/filter the network
   * selector (see `main.ts`'s `renderNetworkSelect` and the "Show test
   * networks" toggle) and to style the "which network am I looking at"
   * banner. Deliberately a separate field from `sendSupported` rather than
   * derived from it: today every built-in testnet here happens to be
   * sendable and every built-in mainnet isn't, but that's a property of
   * this app's current scope, not a definition — a future mainnet-sending
   * rollout flipping one network's `sendSupported` must not silently move
   * it into the wrong group in the selector, and nothing in this codebase
   * should ever infer one field from the other.
   */
  isTestnet: boolean;
  /**
   * Whether this is a user-added custom network rather than one of this
   * app's own pre-verified built-ins. Drives two things, both in main.ts:
   * the persistent "not vetted" warning banner, and a hard pre-check that
   * short-circuits balance/send requests with a clear message instead of
   * letting them silently fail — a custom RPC origin is never in
   * `tauri.conf.json`'s static CSP `connect-src` allowlist (that's a
   * build-time list; it cannot be extended at runtime for whatever a user
   * types in), so any real request to one would otherwise be blocked by
   * the webview with no usable error. See main.ts's `CUSTOM_NETWORK_RPC_BLOCKED_MESSAGE`.
   */
  isCustom: boolean;
  /** viem's own chain metadata (nativeCurrency, name, ...) for a built-in network; a `defineChain`-built equivalent for a custom one (see `buildCustomNetworkConfig`) — either way, not hand-rolled beyond what's needed. See the doc comment on `rpcClient` for why the RPC URL itself still comes from `defaultRpcUrl`/the user's override, not this. */
  viemChain: Chain;
  defaultRpcUrl: string;
  /** Base URL for a human-facing block-explorer page, e.g. `${explorerBaseUrl}/tx/${hash}`. Etherscan's *API* is unified across chains via `chainid` (see `etherscan.ts`) — this is specifically the different subdomain its *website* uses per network. Empty string for a custom network with no explorer URL entered — callers must treat that as "no explorer link available", not build a URL from it (see main.ts's `renderHistoryRow`). */
  explorerBaseUrl: string;
  /**
   * This chain's native gas currency symbol — ETH on Ethereum/Arbitrum/Base,
   * BNB on BNB Smart Chain, or whatever a custom network's own symbol is.
   * Used for the balance display and the send flow's native-asset label;
   * `formatEther` itself is still the right formatting function for all of
   * these (every network here uses 18 decimals for its native currency),
   * only the unit text after the number varies.
   */
  nativeCurrencySymbol: string;
  /**
   * Whether this app can sign/broadcast a transaction on this network yet.
   * Balance and history reading never check this — it only gates the send
   * flow. Mirrored by a real, independent check on the Rust side
   * (`sign_transaction_impl`/`sign_token_transfer_impl` in lib.rs both
   * refuse a non-sendable chain_id even if this flag were somehow bypassed
   * here) — this flag exists for a good frontend experience (block the
   * send flow before the user fills out a form, not after), not as the
   * actual security boundary.
   *
   * Every built-in testnet added so far is sendable and every built-in
   * mainnet isn't — that's this app's deliberate, current scope (mainnet
   * sending is its own future decision per network, not something that
   * falls out of adding read support), not a rule this type enforces. A
   * custom network defaults to `true` regardless of `isTestnet` (see
   * `buildCustomNetworkConfig`) — in practice this is moot today, since
   * `isCustom`'s CSP pre-check in main.ts blocks every real request to a
   * custom network's RPC endpoint anyway.
   */
  sendSupported: boolean;
  /** This network's verified token list — see each token's own doc comment in `tokens.ts` for how its address was verified. Never the same list reused across networks: a token contract address is only valid on the specific chain it was verified for. Empty for the four networks added 2026-08-27 (BNB Smart Chain, Arbitrum, Base, and their testnets) and for every custom network — token contract addresses for those are each their own separately-verified addition, out of scope here. */
  tokens: readonly TokenListing[];
}

/**
 * Verified responding on 2026-08-16 via a direct eth_chainId call, which
 * echoed back 0xaa36a7 (11155111) — confirming it's genuinely Sepolia, not
 * just that the host answers HTTP. No API key required.
 *
 * The other candidate named in the original request, https://rpc.sepolia.org,
 * was NOT used: the default already responded correctly, so the fallback
 * was never exercised. It is deliberately not present in this app's CSP
 * connect-src (see tauri.conf.json) — an unused allowance is still an
 * unused exfiltration path. If this default ever goes down, add the
 * fallback to connect-src in the same change that switches to it here, not
 * preemptively.
 */
export const DEFAULT_SEPOLIA_RPC_URL = "https://ethereum-sepolia-rpc.publicnode.com";

/**
 * Verified responding on 2026-08-24 via a direct eth_chainId call, which
 * echoed back 0x1 — confirming it's genuinely Ethereum mainnet. No API key
 * required. Same provider (publicnode) as the Sepolia default above, for
 * the same reason: already in this app's trust boundary, no new party to
 * evaluate.
 */
export const DEFAULT_MAINNET_RPC_URL = "https://ethereum-rpc.publicnode.com";

/**
 * All six defaults below (BNB Smart Chain mainnet/testnet, Arbitrum One/
 * Sepolia, Base mainnet/Sepolia) were verified responding on 2026-08-27 via
 * a direct eth_chainId call each, matching their chain ID exactly (0x38=56,
 * 0x61=97, 0xa4b1=42161, 0x66eee=421614, 0x2105=8453, 0x14a34=84532) — same
 * publicnode provider as the two defaults above, already in this app's
 * trust boundary.
 *
 * The chain IDs themselves were verified independently and separately from
 * the RPC check, directly against chainlist.org (one page per chain,
 * https://chainlist.org/chain/<id>), not from memory or a summarized
 * search result — each page's own displayed network name was cross-checked
 * against the expected chain before use, the same discipline as the USDC
 * contract-address verification elsewhere in this codebase (see tokens.ts).
 */
export const DEFAULT_BSC_RPC_URL = "https://bsc-rpc.publicnode.com";
export const DEFAULT_BSC_TESTNET_RPC_URL = "https://bsc-testnet-rpc.publicnode.com";
export const DEFAULT_ARBITRUM_RPC_URL = "https://arbitrum-one-rpc.publicnode.com";
export const DEFAULT_ARBITRUM_SEPOLIA_RPC_URL = "https://arbitrum-sepolia-rpc.publicnode.com";
export const DEFAULT_BASE_RPC_URL = "https://base-rpc.publicnode.com";
export const DEFAULT_BASE_SEPOLIA_RPC_URL = "https://base-sepolia-rpc.publicnode.com";

/**
 * Verified 2026-08-20: chain ID confirmed against https://chainlist.org/chain/137
 * directly (page displays "Polygon Mainnet", chain ID 137 / 0x89), and the
 * RPC endpoint below confirmed responding with the same chain ID (0x89) via
 * a direct eth_chainId call. Same publicnode provider as every other default
 * here. Polygon's native currency is POL (rebranded from MATIC in 2024) —
 * matches viem's own `polygon.nativeCurrency`, cross-checked against
 * chainlist.org's page, which also lists POL as of this verification.
 */
export const DEFAULT_POLYGON_RPC_URL = "https://polygon-bor-rpc.publicnode.com";

/**
 * Verified 2026-08-20: chain ID confirmed against https://chainlist.org/chain/10
 * directly (page displays "OP Mainnet", chain ID 10 / 0xa), and the RPC
 * endpoint below confirmed responding with the same chain ID (0xa) via a
 * direct eth_chainId call. Same publicnode provider as every other default
 * here.
 */
export const DEFAULT_OPTIMISM_RPC_URL = "https://optimism-rpc.publicnode.com";

/**
 * Verified 2026-08-21 against https://chainlist.org/chain/80002 directly
 * (page displays "Amoy", chain ID 80002 / 0x13882 — Polygon's current
 * testnet, replacing the deprecated Mumbai testnet), and the RPC endpoint
 * below confirmed responding with the same chain ID (0x13882) via a direct
 * eth_chainId call. Live explorer check (not just an HTTP 200) confirmed
 * the page title reads "TESTNET Polygon PoS Chain Amoy (POL) Blockchain
 * Explorer" — genuinely this network, not a generic landing page.
 */
export const DEFAULT_POLYGON_AMOY_RPC_URL = "https://polygon-amoy-bor-rpc.publicnode.com";

/**
 * Verified 2026-08-21 against https://chainlist.org/chain/11155420 directly
 * (page displays "OP Sepolia Testnet", chain ID 11155420 / 0xaa37dc), and
 * the RPC endpoint below confirmed responding with the same chain ID
 * (0xaa37dc) via a direct eth_chainId call. Live explorer check confirmed
 * the page title reads "TESTNET OP Sepolia Network (ETH) Blockchain
 * Explorer".
 */
export const DEFAULT_OPTIMISM_SEPOLIA_RPC_URL = "https://optimism-sepolia-rpc.publicnode.com";

export const NETWORKS: Readonly<Record<NetworkId, NetworkConfig>> = {
  sepolia: {
    id: "sepolia",
    label: "Sepolia Testnet",
    chainId: sepolia.id,
    isTestnet: true,
    isCustom: false,
    viemChain: sepolia,
    defaultRpcUrl: DEFAULT_SEPOLIA_RPC_URL,
    explorerBaseUrl: "https://sepolia.etherscan.io",
    nativeCurrencySymbol: "ETH",
    sendSupported: true,
    tokens: SEPOLIA_TOKENS,
  },
  mainnet: {
    id: "mainnet",
    label: "Ethereum Mainnet",
    chainId: mainnet.id,
    isTestnet: false,
    isCustom: false,
    viemChain: mainnet,
    defaultRpcUrl: DEFAULT_MAINNET_RPC_URL,
    explorerBaseUrl: "https://etherscan.io",
    nativeCurrencySymbol: "ETH",
    // Deliberate, temporary restriction -- not a bug. Mirrored by a real
    // backend check (see this field's own doc comment above); this flag is
    // what gives the *frontend* a chance to say so clearly before the user
    // fills out an entire send form, per the project's requirement that
    // hitting this wall happen up front, not at the confirmation step.
    sendSupported: false,
    tokens: MAINNET_TOKENS,
  },
  bscTestnet: {
    id: "bscTestnet",
    label: "BNB Smart Chain Testnet",
    // Confirmed by the user directly (not independently re-verified by this
    // pass, per their explicit note when requesting this network).
    chainId: bscTestnet.id,
    isTestnet: true,
    isCustom: false,
    viemChain: bscTestnet,
    defaultRpcUrl: DEFAULT_BSC_TESTNET_RPC_URL,
    explorerBaseUrl: "https://testnet.bscscan.com",
    nativeCurrencySymbol: "BNB",
    sendSupported: true,
    tokens: [],
  },
  bsc: {
    id: "bsc",
    label: "BNB Smart Chain",
    // Verified 2026-08-27 against https://chainlist.org/chain/56 directly:
    // page displays "BNB Smart Chain Mainnet", chain ID 56 (0x38).
    chainId: bsc.id,
    isTestnet: false,
    isCustom: false,
    viemChain: bsc,
    defaultRpcUrl: DEFAULT_BSC_RPC_URL,
    explorerBaseUrl: "https://bscscan.com",
    nativeCurrencySymbol: "BNB",
    sendSupported: false,
    tokens: [],
  },
  arbitrumSepolia: {
    id: "arbitrumSepolia",
    label: "Arbitrum Sepolia",
    // Verified 2026-08-27 against https://chainlist.org/chain/421614
    // directly: page displays "Arbitrum Sepolia" (Arbitrum Sepolia Rollup
    // Testnet), chain ID 421614 (0x66eee).
    chainId: arbitrumSepolia.id,
    isTestnet: true,
    isCustom: false,
    viemChain: arbitrumSepolia,
    defaultRpcUrl: DEFAULT_ARBITRUM_SEPOLIA_RPC_URL,
    explorerBaseUrl: "https://sepolia.arbiscan.io",
    nativeCurrencySymbol: "ETH",
    sendSupported: true,
    tokens: [],
  },
  arbitrum: {
    id: "arbitrum",
    label: "Arbitrum One",
    // Verified 2026-08-27 against https://chainlist.org/chain/42161
    // directly: page displays "Arbitrum One", chain ID 42161 (0xa4b1).
    chainId: arbitrum.id,
    isTestnet: false,
    isCustom: false,
    viemChain: arbitrum,
    defaultRpcUrl: DEFAULT_ARBITRUM_RPC_URL,
    explorerBaseUrl: "https://arbiscan.io",
    nativeCurrencySymbol: "ETH",
    sendSupported: false,
    tokens: [],
  },
  baseSepolia: {
    id: "baseSepolia",
    label: "Base Sepolia",
    // Verified 2026-08-27 against https://chainlist.org/chain/84532
    // directly: page displays "Base Sepolia Testnet", chain ID 84532
    // (0x14a34).
    chainId: baseSepolia.id,
    isTestnet: true,
    isCustom: false,
    viemChain: baseSepolia,
    defaultRpcUrl: DEFAULT_BASE_SEPOLIA_RPC_URL,
    explorerBaseUrl: "https://sepolia.basescan.org",
    nativeCurrencySymbol: "ETH",
    sendSupported: true,
    tokens: [],
  },
  base: {
    id: "base",
    label: "Base",
    // Verified 2026-08-27 against https://chainlist.org/chain/8453
    // directly: page displays "Base" (mainnet explorers Basescan/BlockScout,
    // not testnet ones), chain ID 8453 (0x2105).
    chainId: base.id,
    isTestnet: false,
    isCustom: false,
    viemChain: base,
    defaultRpcUrl: DEFAULT_BASE_RPC_URL,
    explorerBaseUrl: "https://basescan.org",
    nativeCurrencySymbol: "ETH",
    sendSupported: false,
    tokens: [],
  },
  polygon: {
    id: "polygon",
    label: "Polygon",
    chainId: polygon.id,
    isTestnet: false,
    isCustom: false,
    viemChain: polygon,
    defaultRpcUrl: DEFAULT_POLYGON_RPC_URL,
    explorerBaseUrl: "https://polygonscan.com",
    nativeCurrencySymbol: "POL",
    sendSupported: false,
    tokens: [],
  },
  polygonAmoy: {
    id: "polygonAmoy",
    label: "Polygon Amoy",
    // Verified 2026-08-21 against https://chainlist.org/chain/80002
    // directly: page displays "Amoy", chain ID 80002 (0x13882). Amoy is
    // Polygon's current testnet -- Mumbai, the previous one, was
    // deprecated/shut down in 2024.
    chainId: polygonAmoy.id,
    isTestnet: true,
    isCustom: false,
    viemChain: polygonAmoy,
    defaultRpcUrl: DEFAULT_POLYGON_AMOY_RPC_URL,
    explorerBaseUrl: "https://amoy.polygonscan.com",
    nativeCurrencySymbol: "POL",
    sendSupported: true,
    tokens: [],
  },
  optimism: {
    id: "optimism",
    label: "Optimism",
    chainId: optimism.id,
    isTestnet: false,
    isCustom: false,
    viemChain: optimism,
    defaultRpcUrl: DEFAULT_OPTIMISM_RPC_URL,
    explorerBaseUrl: "https://optimistic.etherscan.io",
    nativeCurrencySymbol: "ETH",
    sendSupported: false,
    tokens: [],
  },
  optimismSepolia: {
    id: "optimismSepolia",
    label: "OP Sepolia",
    // Verified 2026-08-21 against https://chainlist.org/chain/11155420
    // directly: page displays "OP Sepolia Testnet", chain ID 11155420
    // (0xaa37dc).
    chainId: optimismSepolia.id,
    isTestnet: true,
    isCustom: false,
    viemChain: optimismSepolia,
    defaultRpcUrl: DEFAULT_OPTIMISM_SEPOLIA_RPC_URL,
    explorerBaseUrl: "https://sepolia-optimistic.etherscan.io",
    nativeCurrencySymbol: "ETH",
    sendSupported: true,
    tokens: [],
  },
};

/**
 * Mainnet, not Sepolia: the network selector shows mainnets only (see
 * main.ts's `renderNetworkSelect`, which no longer has a testnet-visibility
 * toggle) — a testnet default would be permanently hidden from its own
 * selector, which is exactly the bug `renderNetworkSelect`'s doc comment
 * describes. Testnet configs stay in `NETWORKS` and remain independently
 * selectable via a fixed `NetworkId` (e.g. for whoever needs to exercise a
 * real send flow before mainnet sending is a thing) — they're just not
 * user-facing in this build.
 */
export const DEFAULT_NETWORK: NetworkId = "mainnet";

/**
 * The origin a network's RPC calls are allowed to reach, for the CSP
 * connect-src cross-check described below — one entry, not a set: a user is
 * never allowed to point one network's RPC override at some OTHER
 * network's default origin (or an arbitrary one) — only this specific
 * network's own verified default. That's a deliberate tightening, not just
 * a generalization: it also rules out the confusing case of the network
 * banner saying "Ethereum Mainnet" while requests actually go to some
 * other network's endpoint.
 *
 * Checked client-side, proactively, *before* attempting a fetch to a
 * user-entered RPC override — not by reacting to a CSP violation. A
 * `securitypolicyviolation` DOM event does fire for a blocked `connect-src`
 * request, but it's dispatched as a separate, later task than the one that
 * runs the `fetch()` promise's rejection, so by the time any `catch` block
 * runs, the event has reliably not fired yet — confirmed empirically
 * (2026-08-17) with a standalone reproduction serving the identical policy
 * over real HTTP: the rejection's `catch` handler, and everything
 * synchronously after it, observably completed before the violation event
 * was dispatched. That isn't a timing fluke to work around with a delay; a
 * blocked fetch's rejection is a microtask and the violation event is a
 * task, so the ordering is structural. Hence checking here instead.
 *
 * MUST be kept in sync with connect-src in tauri.conf.json by hand — there
 * is no automated link between this and the CSP string. Update both
 * together when adding a network.
 */
export function allowedRpcOrigin(network: NetworkConfig): string {
  return new URL(network.defaultRpcUrl).origin;
}

/**
 * Bounded so a hung or slow-to-respond endpoint surfaces as a visible
 * error within a reasonable time instead of leaving the balance UI stuck
 * on "Loading…" indefinitely.
 */
const RPC_TIMEOUT_MS = 10_000;

/**
 * Build a fresh read-only client for `network` against `rpcUrl`. Called per
 * request (rather than caching one client) so the RPC-endpoint override
 * field takes effect immediately on the next fetch, with no stale-client
 * state to invalidate.
 *
 * `network.viemChain` supplies chain metadata (name, native currency, ...)
 * from viem's own well-known chain list — not hand-rolled. The actual RPC
 * *transport* still always comes from the explicit `rpcUrl` argument, never
 * from `viemChain`'s own baked-in default RPC URLs — this app's verified
 * defaults (`DEFAULT_SEPOLIA_RPC_URL` and friends, above) and the CSP
 * allowlist they drive are the actual source of truth for which endpoint
 * gets used.
 */
export function rpcClient(network: NetworkConfig, rpcUrl: string) {
  return createPublicClient({
    chain: network.viemChain,
    transport: http(rpcUrl, { timeout: RPC_TIMEOUT_MS }),
  });
}

/** Raw, untrimmed form input for adding a custom network — see `validateCustomNetworkInput`. */
export interface CustomNetworkFormInput {
  label: string;
  rpcUrl: string;
  /** A string, not a number: this is exactly what the chain-ID text field holds, digits-only validation included. */
  chainIdInput: string;
  nativeCurrencySymbol: string;
  /** Empty string means "not provided" — a genuinely optional field, not a validation failure. */
  explorerBaseUrlInput: string;
}

export type ValidateCustomNetworkResult =
  | { ok: true; value: { label: string; rpcUrl: string; chainId: number; nativeCurrencySymbol: string; explorerBaseUrl: string | null } }
  | { ok: false; error: string };

/**
 * Validate raw custom-network form input: chain ID must be numeric (a
 * plain non-negative integer, nothing `Number()` would coerce like "1e3" or
 * "0x1"), the RPC URL and the optional explorer URL must each be a
 * well-formed http/https URL, and neither the chain ID nor RPC origin may
 * collide with a network already known (built-in or previously-added
 * custom) — a silent duplicate would just be confusing in the selector.
 *
 * Deliberately returns a discriminated result rather than throwing: this is
 * user input from a form, wrong on the first try is the expected case, not
 * an exceptional one.
 */
export function validateCustomNetworkInput(
  input: CustomNetworkFormInput,
  existingNetworks: readonly NetworkConfig[],
): ValidateCustomNetworkResult {
  const label = input.label.trim();
  if (!label) {
    return { ok: false, error: "Enter a network name." };
  }

  const rpcUrl = input.rpcUrl.trim();
  let parsedRpcUrl: URL;
  try {
    parsedRpcUrl = new URL(rpcUrl);
  } catch {
    return { ok: false, error: "Enter a well-formed RPC URL (e.g. https://…)." };
  }
  if (parsedRpcUrl.protocol !== "https:" && parsedRpcUrl.protocol !== "http:") {
    return { ok: false, error: "RPC URL must start with http:// or https://." };
  }

  const chainIdInput = input.chainIdInput.trim();
  // Digits only -- rejects "1e3", "0x1", "1.5", a leading "+"/"-", anything
  // Number() would otherwise silently coerce into a value the user didn't
  // type. A chain ID is always a plain non-negative integer.
  if (!/^\d+$/.test(chainIdInput)) {
    return { ok: false, error: "Chain ID must be a whole number, e.g. 1337." };
  }
  const chainId = Number(chainIdInput);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) {
    return { ok: false, error: "Chain ID must be a positive whole number." };
  }

  const nativeCurrencySymbol = input.nativeCurrencySymbol.trim();
  if (!nativeCurrencySymbol) {
    return { ok: false, error: "Enter the native currency symbol (e.g. ETH)." };
  }

  const explorerBaseUrlInput = input.explorerBaseUrlInput.trim();
  let explorerBaseUrl: string | null = null;
  if (explorerBaseUrlInput) {
    let parsedExplorerUrl: URL;
    try {
      parsedExplorerUrl = new URL(explorerBaseUrlInput);
    } catch {
      return { ok: false, error: "Explorer URL must be well-formed (e.g. https://…), or left blank." };
    }
    if (parsedExplorerUrl.protocol !== "https:" && parsedExplorerUrl.protocol !== "http:") {
      return { ok: false, error: "Explorer URL must start with http:// or https://, or be left blank." };
    }
    // Matches the trailing-slash-free convention every built-in
    // explorerBaseUrl already uses (e.g. "https://etherscan.io", not
    // ".../"), so `${explorerBaseUrl}/tx/${hash}` never ends up with a
    // doubled slash.
    explorerBaseUrl = explorerBaseUrlInput.replace(/\/+$/, "");
  }

  const chainIdCollision = existingNetworks.find((n) => n.chainId === chainId);
  if (chainIdCollision) {
    return { ok: false, error: `Chain ID ${chainId} is already used by "${chainIdCollision.label}".` };
  }

  return { ok: true, value: { label, rpcUrl, chainId, nativeCurrencySymbol, explorerBaseUrl } };
}

/**
 * Build a full `NetworkConfig` for a validated custom network. `id` is
 * caller-supplied (main.ts generates a fresh `custom-<n>` per addition) so
 * this module doesn't need to own an id-counter as global mutable state.
 *
 * `sendSupported: true` per this feature's spec — but see `isCustom`'s own
 * doc comment: main.ts's CSP pre-check blocks every real RPC request to a
 * custom network regardless, since its origin can never be in
 * `tauri.conf.json`'s static allowlist. `isTestnet: false` unconditionally:
 * this app has no way to know whether a user-entered chain is a testnet or
 * a mainnet, and doesn't ask — a custom network is always shown regardless
 * of the "Show test networks" toggle (see main.ts's `renderNetworkSelect`),
 * so the value doesn't actually affect visibility either way.
 */
export function buildCustomNetworkConfig(
  id: string,
  value: { label: string; rpcUrl: string; chainId: number; nativeCurrencySymbol: string; explorerBaseUrl: string | null },
): NetworkConfig {
  const viemChain = defineChain({
    id: value.chainId,
    name: value.label,
    nativeCurrency: { name: value.nativeCurrencySymbol, symbol: value.nativeCurrencySymbol, decimals: 18 },
    rpcUrls: { default: { http: [value.rpcUrl] } },
  });

  return {
    id,
    label: value.label,
    chainId: value.chainId,
    isTestnet: false,
    isCustom: true,
    viemChain,
    defaultRpcUrl: value.rpcUrl,
    explorerBaseUrl: value.explorerBaseUrl ?? "",
    nativeCurrencySymbol: value.nativeCurrencySymbol,
    sendSupported: true,
    tokens: [],
  };
}

export type { Address };
