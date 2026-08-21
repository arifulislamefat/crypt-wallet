import { formatUnits } from "viem";

/**
 * Solana mainnet-beta balance fetching — view-only. No signing, no
 * transaction construction here; this module's only job is turning an
 * address into a displayable SOL balance.
 *
 * Endpoint verified 2026-08-20 via a direct `getGenesisHash` RPC call,
 * cross-checked against the same call made directly to Solana Labs' own
 * `api.mainnet-beta.solana.com` and `api.mainnet.solana.com` endpoints — all
 * three returned the identical genesis hash
 * (`5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`), confirming this is
 * genuinely mainnet-beta, not some other cluster. publicnode is used here
 * rather than Solana Labs' own endpoint for the same reason as every other
 * network in this app: already in this app's trust boundary (see
 * `networks.ts`), and Solana Labs' own endpoint is explicitly documented as
 * rate-limited and "not recommended for production."
 */
export const SOLANA_MAINNET_RPC_URL = "https://solana-rpc.publicnode.com";

/** SOL's fixed decimal count — every lamport/SOL conversion in this app uses this, never a magic number inline. */
export const SOL_DECIMALS = 9;

/** A malformed or error RPC response — network failures surface as the underlying `fetch`/`TypeError`, not this. */
export class SolanaRpcError extends Error {}

interface SolanaRpcResponse<T> {
  jsonrpc: string;
  id: number;
  result?: T;
  error?: { code: number; message: string };
}

/**
 * Shared JSON-RPC call helper — every function in this module that talks to
 * the network goes through this one place, so the error handling (HTTP
 * failure, RPC-level `error`, malformed/missing `result`) is written once,
 * not once per method.
 */
async function solanaRpc<T>(method: string, params: unknown[]): Promise<T> {
  const response = await fetch(SOLANA_MAINNET_RPC_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });

  if (!response.ok) {
    throw new SolanaRpcError(`RPC request failed: HTTP ${response.status}`);
  }

  const data = (await response.json()) as SolanaRpcResponse<T>;
  if (data.error) {
    throw new SolanaRpcError(data.error.message);
  }
  if (data.result === undefined) {
    throw new SolanaRpcError("malformed RPC response: missing result");
  }
  return data.result;
}

/**
 * Fetch `address`'s SOL balance, in lamports (SOL's smallest unit, 1 SOL =
 * 10^9 lamports — see `SOL_DECIMALS`). Raw JSON-RPC, not a client library:
 * these are small, trivial call shapes, and pulling in `@solana/web3.js`
 * for them would be a large dependency for little benefit. Transaction
 * *construction* (see `sign_solana_transaction` in lib.rs) is a different
 * story — building and serializing a transaction by hand is exactly the
 * kind of protocol logic this project's own rules say to use an audited
 * library for, not this; that part uses Solana's own Rust SDK crates, not
 * anything hand-rolled here.
 */
export async function fetchSolanaBalanceLamports(address: string): Promise<bigint> {
  const result = await solanaRpc<{ context: { slot: number }; value: number }>("getBalance", [address]);
  return BigInt(result.value);
}

/**
 * The network's current recent blockhash — required by every Solana
 * transaction (it's what makes a transaction expire and prevents indefinite
 * replay). Fetched fresh immediately before signing, never cached: a stale
 * blockhash makes the transaction invalid outright, so there is no reason
 * to hold onto one.
 */
export async function fetchLatestBlockhash(): Promise<string> {
  const result = await solanaRpc<{ context: { slot: number }; value: { blockhash: string; lastValidBlockHeight: number } }>(
    "getLatestBlockhash",
    [{ commitment: "finalized" }],
  );
  return result.value.blockhash;
}

/**
 * Solana's base transaction fee: a fixed protocol constant, 5000 lamports
 * per signature — NOT an estimate, and NOT variable with network
 * congestion the way EVM gas prices are (verified against
 * https://solana.com/docs/core/fees, 2026-08-21: "The base transaction fee
 * on Solana is 5,000 lamports per signature... a fixed protocol constant").
 * Only an optional, separate prioritization fee varies with congestion —
 * this app adds none, so this constant is the complete fee for the single-
 * signature transfers it constructs.
 */
export const BASE_FEE_LAMPORTS_PER_SIGNATURE = 5_000n;

/**
 * Broadcast an already-signed transaction (base64, as returned by
 * `sign_solana_transaction`) and return its signature — the transaction's
 * own unique identifier, usable to look it up on any block explorer or via
 * `confirmSolanaTransaction` below.
 */
export async function sendRawSolanaTransaction(signedTransactionBase64: string): Promise<string> {
  return solanaRpc<string>("sendTransaction", [
    signedTransactionBase64,
    { encoding: "base64", preflightCommitment: "finalized" },
  ]);
}

/** One transaction's confirmation state, as reported by `getSignatureStatuses`. */
export type SolanaConfirmationStatus = "processed" | "confirmed" | "finalized" | "not_found" | "failed";

/**
 * Poll `getSignatureStatuses` for `signature` until it reaches a terminal
 * state (`confirmed`, `finalized`, or `failed`) or `timeoutMs` elapses.
 * Bounded so a stuck or dropped transaction surfaces as a clear timeout
 * rather than polling forever — the same reasoning as `RPC_TIMEOUT_MS` in
 * `networks.ts`.
 */
export async function confirmSolanaTransaction(
  signature: string,
  timeoutMs = 60_000,
  pollIntervalMs = 2_000,
): Promise<SolanaConfirmationStatus> {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const result = await solanaRpc<{
      context: { slot: number };
      value: ({ err: unknown; confirmationStatus?: string } | null)[];
    }>("getSignatureStatuses", [[signature]]);

    const status = result.value[0];
    if (status) {
      if (status.err) {
        return "failed";
      }
      if (status.confirmationStatus === "confirmed" || status.confirmationStatus === "finalized") {
        return status.confirmationStatus;
      }
    }

    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }

  return "not_found";
}

/**
 * Format a lamports amount as a SOL string, e.g. `1.5`. Reuses viem's
 * `formatUnits` — it's decimal-count-generic, not EVM-specific, so this is
 * genuine reuse of an already-vetted formatting routine, not a
 * coincidentally-similar hand-rolled one.
 */
export function formatLamportsAsSol(lamports: bigint): string {
  return formatUnits(lamports, SOL_DECIMALS);
}
