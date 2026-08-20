import { erc20Abi } from "viem";
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
export const SEPOLIA_TOKENS: readonly Address[] = [
  "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", // USDC (Circle, verified above)
];

export interface TokenBalance {
  address: Address;
  /** Read from the contract's `symbol()` — never assumed from the address list above. */
  symbol: string;
  /** Read from the contract's `decimals()` — never assumed, not even 6 for USDC. See module doc. */
  decimals: number;
  /** Raw on-chain balance, in the token's smallest unit. Format with `formatUnits(balance, decimals)`, not `formatEther`. */
  balance: bigint;
}

/**
 * Read one ERC-20 token's balance, symbol, and decimals for `owner`, all
 * live from the contract — three independent `eth_call`s, run concurrently.
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
  const [balance, decimals, symbol] = await Promise.all([
    client.readContract({
      address: tokenAddress,
      abi: erc20Abi,
      functionName: "balanceOf",
      args: [owner],
    }),
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

  return { address: tokenAddress, symbol, decimals, balance };
}
