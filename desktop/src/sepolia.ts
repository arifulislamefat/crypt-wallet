import { createPublicClient, http, defineChain, type Address } from "viem";

/**
 * Sepolia testnet. Read-only — this module never touches signing, seeds, or
 * the vault, so it's independent of everything in `main.ts`'s secret-
 * handling flow. It only ever moves an address (public) out and a balance
 * (public) back.
 */
export const SEPOLIA_CHAIN_ID = 11155111;

/**
 * Verified responding on 2026-08-16 via a direct eth_chainId call, which
 * echoed back 0xaa36a7 (11155111) — confirming it's genuinely Sepolia, not
 * just that the host answers HTTP. No API key required.
 *
 * The other candidate named in the request, https://rpc.sepolia.org, was
 * NOT used: the default already responded correctly, so the fallback was
 * never exercised. It is deliberately not present in this app's CSP
 * connect-src (see tauri.conf.json) — an unused allowance is still an
 * unused exfiltration path. If this default ever goes down, add the
 * fallback to connect-src in the same change that switches to it here,
 * not preemptively.
 */
export const DEFAULT_SEPOLIA_RPC_URL = "https://ethereum-sepolia-rpc.publicnode.com";

/**
 * Origins this app's CSP `connect-src` actually allows for RPC calls (see
 * `desktop/src-tauri/tauri.conf.json`). One entry today, matching
 * `DEFAULT_SEPOLIA_RPC_URL` above.
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
 * MUST be kept in sync with connect-src by hand — there is no automated
 * link between this list and the CSP string in tauri.conf.json. Update
 * both together.
 */
export const ALLOWED_RPC_ORIGINS: ReadonlySet<string> = new Set([
  new URL(DEFAULT_SEPOLIA_RPC_URL).origin,
]);

const sepolia = defineChain({
  id: SEPOLIA_CHAIN_ID,
  name: "Sepolia",
  nativeCurrency: { name: "Sepolia Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: {
    default: { http: [DEFAULT_SEPOLIA_RPC_URL] },
  },
  testnet: true,
});

/**
 * Bounded so a hung or slow-to-respond endpoint surfaces as a visible
 * error within a reasonable time instead of leaving the balance UI stuck
 * on "Loading…" indefinitely.
 */
const RPC_TIMEOUT_MS = 10_000;

/**
 * Build a fresh read-only client against `rpcUrl`. Called per-request
 * (rather than caching one client) so the RPC-endpoint override field takes
 * effect immediately on the next fetch, with no stale-client state to
 * invalidate.
 */
export function sepoliaClient(rpcUrl: string) {
  return createPublicClient({
    chain: sepolia,
    transport: http(rpcUrl, { timeout: RPC_TIMEOUT_MS }),
  });
}

export type { Address };
