import { erc20Abi, parseUnits } from "viem";
import type { Address } from "./sepolia";
import type { sepoliaClient } from "./sepolia";

/**
 * Hardcoded ERC-20 token list for the Sepolia balance display. Adding a
 * token later is a one-line addition here — nothing else in this module or
 * in `main.ts`'s rendering needs to change, since symbol and decimals are
 * always read from the contract itself (see `fetchTokenBalance`), never
 * assumed from this list.
 *
 * ## Sepolia USDC address verification (2026-08-20)
 *
 * `0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238`, cross-checked two ways
 * before use, per the project's rule of never trusting a contract address
 * from a single or third-party source:
 *
 * 1. Circle's own developer docs, fetched directly (not via search-engine
 *    summary — an earlier search result for this exact query returned
 *    addresses for other test networks that were the wrong length,
 *    i.e. fabricated, which is exactly the failure mode this rule exists
 *    to catch): https://developers.circle.com/stablecoins/usdc-contract-addresses,
 *    "Ethereum Sepolia" row.
 * 2. Sepolia Etherscan for that address: the TokenTracker labels it
 *    `ERC-20: USDC (USDC)` at 6 decimals, and its verified source code
 *    (exact match) is Circle's own `FiatTokenProxy` contract — the same
 *    proxy contract name Circle uses for every real USDC deployment — with
 *    the verified source path itself containing
 *    `stablecoin-evm-private-usdc-eth-testnet`, Circle's own internal
 *    testnet-deployment repo naming. A scam token reusing the "USDC" name
 *    would not independently have Circle's real, audited proxy bytecode
 *    verified against Circle's own source tree.
 */
export interface TokenListing {
  address: Address;
  /**
   * Cosmetic UI label only — populates the token selector's option text
   * before its real `symbol()` has been fetched. Never used for anything
   * that touches chain data or an amount: the send flow and balance display
   * both always use the contract-read `symbol`/`decimals` from
   * `fetchTokenMetadata`, never this field.
   */
  label: string;
}

/**
 * Hardcoded ERC-20 token list for the Sepolia balance display and the send
 * flow's token selector. Adding a token later is a one-line addition here —
 * nothing else in this module or in `main.ts` needs to change, since symbol
 * and decimals are always read from the contract itself (see
 * `fetchTokenMetadata`), never assumed from this list.
 *
 * ## Sepolia USDC address verification (2026-08-20)
 *
 * `0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238`, cross-checked two ways
 * before use, per the project's rule of never trusting a contract address
 * from a single or third-party source:
 *
 * 1. Circle's own developer docs, fetched directly (not via search-engine
 *    summary — an earlier search result for this exact query returned
 *    addresses for other test networks that were the wrong length,
 *    i.e. fabricated, which is exactly the failure mode this rule exists
 *    to catch): https://developers.circle.com/stablecoins/usdc-contract-addresses,
 *    "Ethereum Sepolia" row.
 * 2. Sepolia Etherscan for that address: the TokenTracker labels it
 *    `ERC-20: USDC (USDC)` at 6 decimals, and its verified source code
 *    (exact match) is Circle's own `FiatTokenProxy` contract — the same
 *    proxy contract name Circle uses for every real USDC deployment — with
 *    the verified source path itself containing
 *    `stablecoin-evm-private-usdc-eth-testnet`, Circle's own internal
 *    testnet-deployment repo naming. A scam token reusing the "USDC" name
 *    would not independently have Circle's real, audited proxy bytecode
 *    verified against Circle's own source tree.
 */
export const SEPOLIA_TOKENS: readonly TokenListing[] = [
  { address: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", label: "USDC" }, // Circle, verified above
];

export interface TokenMetadata {
  /** Read from the contract's `symbol()` — never assumed from `SEPOLIA_TOKENS`'s `label`. */
  symbol: string;
  /** Read from the contract's `decimals()` — never assumed, not even 6 for USDC. See module doc. */
  decimals: number;
}

export interface TokenBalance extends TokenMetadata {
  address: Address;
  /** Raw on-chain balance, in the token's smallest unit. Format with `formatUnits(balance, decimals)`, not `formatEther`. */
  balance: bigint;
}

/**
 * Read one ERC-20 token's real symbol and decimals, live from the contract.
 * Shared by `fetchTokenBalance` (the balance display) and the send flow's
 * token selector (which needs decimals to convert a human amount to raw
 * units, and doesn't need a balance at all) — one decimals/symbol-reading
 * code path for both, so there's only one place that could get it wrong.
 */
export async function fetchTokenMetadata(
  client: ReturnType<typeof sepoliaClient>,
  tokenAddress: Address,
): Promise<TokenMetadata> {
  const [decimals, symbol] = await Promise.all([
    client.readContract({
      address: tokenAddress,
      abi: erc20Abi,
      functionName: "decimals",
    }),
    client.readContract({
      address: tokenAddress,
      abi: erc20Abi,
      functionName: "symbol",
    }),
  ]);
  return { decimals, symbol };
}

/**
 * Read one ERC-20 token's balance, symbol, and decimals for `owner`, all
 * live from the contract — the balance read runs concurrently with the
 * shared `fetchTokenMetadata` call.
 *
 * Deliberately does not catch errors itself: a failed read here is a
 * per-token concern, and the caller (`fetchTokenBalances` in `main.ts`)
 * decides how to surface that without losing the other tokens' results.
 */
export async function fetchTokenBalance(
  client: ReturnType<typeof sepoliaClient>,
  tokenAddress: Address,
  owner: Address,
): Promise<TokenBalance> {
  const [balance, metadata] = await Promise.all([
    client.readContract({
      address: tokenAddress,
      abi: erc20Abi,
      functionName: "balanceOf",
      args: [owner],
    }),
    fetchTokenMetadata(client, tokenAddress),
  ]);

  return { address: tokenAddress, balance, ...metadata };
}

/**
 * Parse a human decimal amount (e.g. what a user typed for a token send)
 * into the token's raw smallest-unit integer, for an arbitrary `decimals` —
 * the token-send generalization of `main.ts`'s `parseEtherStrict`.
 *
 * Two layers, deliberately kept separate:
 * - The shape check (`/^\d+(\.\d+)?$/`) is the same strict rule
 *   `parseEtherStrict` uses: a plain, non-negative decimal only. No
 *   scientific notation, no sign, nothing `parseFloat` would silently
 *   accept — rejected outright rather than coerced.
 * - The actual fixed-point conversion is delegated to viem's own
 *   `parseUnits` rather than hand-rolled a second time: unlike
 *   `parseEtherStrict` (written before this app had any non-18-decimal
 *   asset, and kept as its own hand-written bigint math), there's no
 *   reason to maintain two implementations of the same conversion, and
 *   viem's is the same trusted library already used for `formatUnits`
 *   throughout this app. This pairing — strict shape check, then a
 *   library call for the arithmetic — is exactly the discipline
 *   `decimals`-off-by-one bugs need: the classic failure mode is silently
 *   using the wrong POWER OF TEN, and that only happens if something
 *   hand-rolls the multiplication instead of asking the token what its
 *   decimals actually are and handing that straight to a function whose
 *   only job is fixed-point conversion.
 */
export function parseUnitsStrict(input: string, decimals: number): bigint {
  if (!/^\d+(\.\d+)?$/.test(input)) {
    throw new Error("not a valid decimal amount");
  }
  return parseUnits(input, decimals);
}
