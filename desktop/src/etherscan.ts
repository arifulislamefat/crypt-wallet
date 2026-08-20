import type { Address } from "./sepolia";

/**
 * Read-only Sepolia transaction history, via Etherscan's V2 API.
 *
 * Independent of everything in `main.ts`'s secret-handling flow, same as
 * `sepolia.ts` — this module only ever moves an address (public) out and a
 * list of already-broadcast transactions (public) back. No signing, no
 * vault, no passphrase.
 *
 * ## The API key
 *
 * Etherscan's V2 API (`api.etherscan.io/v2/api`) rejects every request
 * without an `apikey` param — verified 2026-08-20 by calling the live
 * Sepolia endpoint with the literal placeholder `YourApiKeyToken`, which
 * came back `{"status":"0","message":"NOTOK","result":"Missing/Invalid API
 * Key"}`. There is no working keyless or public-demo access left; getting a
 * key still requires a free Etherscan account. Free tier is 3 calls/sec,
 * 100,000 calls/day (docs.etherscan.io/rate-limits, checked same day).
 *
 * The key is read from `VITE_ETHERSCAN_API_KEY` (a Vite build-time env var,
 * see `vite-env.d.ts` and the repo's `.env.example`) rather than hardcoded,
 * so swapping in a real key later — or rotating one — never touches this
 * file. `fetchSepoliaTransactions` fails fast with a clear message when it's
 * unset, instead of sending a doomed request.
 */
const ETHERSCAN_API_BASE_URL = "https://api.etherscan.io/v2/api";
const SEPOLIA_CHAIN_ID = 11155111;

/**
 * Most recent transactions to request per fetch. This is a read-only
 * history view, not a full ledger export — 100 covers "what did I just do"
 * for a wallet this young without needing pagination UI yet.
 */
const MAX_RESULTS = 100;

/**
 * Bounded for the same reason as `RPC_TIMEOUT_MS` in sepolia.ts: an
 * unreachable or hung Etherscan should surface as a visible error within a
 * reasonable time, not leave the history view stuck loading indefinitely.
 */
const REQUEST_TIMEOUT_MS = 10_000;

const apiKey = import.meta.env.VITE_ETHERSCAN_API_KEY?.trim() ?? "";

/** True if a key is configured at all — checked before ever touching the network. */
export function hasEtherscanApiKey(): boolean {
  return apiKey.length > 0;
}

/**
 * Distinguishes a "we can't even try" configuration problem (no key set)
 * from a genuine network/API failure — the two need different messages and,
 * for the caller, different next steps (fix a `.env` file vs. "try again
 * later").
 */
export class EtherscanConfigError extends Error {}

/** A real Etherscan request failed — network error, HTTP error, or an API-level error response. */
export class EtherscanApiError extends Error {}

export interface SepoliaTransaction {
  hash: `0x${string}`;
  from: Address;
  /** `null` for a contract-creation transaction, which has no `to`. */
  to: Address | null;
  valueWei: bigint;
  /** Unix seconds. */
  timestamp: number;
  /** `false` also covers the small share of very old pre-Byzantium txs Etherscan can't classify — treated as success, matching Etherscan's own website display. */
  failed: boolean;
}

/**
 * Fetch `address`'s Sepolia transaction list (module=account, action=txlist),
 * newest first.
 *
 * Two failure shapes are deliberately not conflated:
 * - `EtherscanConfigError`: no API key configured. Nothing was sent.
 * - `EtherscanApiError`: a request was made and failed — unreachable host,
 *   timeout, non-2xx HTTP, or an API-level error (bad key, rate limit).
 *
 * An address with no history is not an error: Etherscan reports that as
 * `status: "0", message: "No transactions found"`, which this returns as an
 * empty array rather than throwing.
 */
export async function fetchSepoliaTransactions(
  address: Address,
): Promise<SepoliaTransaction[]> {
  if (!hasEtherscanApiKey()) {
    throw new EtherscanConfigError(
      "No Etherscan API key is configured (set VITE_ETHERSCAN_API_KEY in .env).",
    );
  }

  const url = new URL(ETHERSCAN_API_BASE_URL);
  url.searchParams.set("chainid", String(SEPOLIA_CHAIN_ID));
  url.searchParams.set("module", "account");
  url.searchParams.set("action", "txlist");
  url.searchParams.set("address", address);
  url.searchParams.set("startblock", "0");
  url.searchParams.set("endblock", "99999999");
  url.searchParams.set("page", "1");
  url.searchParams.set("offset", String(MAX_RESULTS));
  url.searchParams.set("sort", "desc");
  url.searchParams.set("apikey", apiKey);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(url, { signal: controller.signal });
  } catch (error) {
    throw new EtherscanApiError(
      `Could not reach Etherscan: ${error instanceof Error ? error.message : String(error)}`,
    );
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    throw new EtherscanApiError(`Etherscan returned HTTP ${response.status}.`);
  }

  const body: unknown = await response.json();
  if (!isEtherscanEnvelope(body)) {
    throw new EtherscanApiError("Etherscan returned an unrecognized response shape.");
  }

  if (body.status === "0") {
    if (body.message === "No transactions found") {
      return [];
    }
    // Etherscan puts the actual explanation (rate limited, bad key, ...) in
    // `result` as a string on this path; fall back to `message` if it
    // isn't, rather than surfacing nothing.
    throw new EtherscanApiError(
      typeof body.result === "string" ? body.result : body.message,
    );
  }

  if (!Array.isArray(body.result)) {
    throw new EtherscanApiError("Etherscan returned an unrecognized response shape.");
  }

  const transactions = body.result.map(parseTransaction);
  // Newest first is also requested via `sort=desc`, but sorted again here
  // rather than trusted blind — cheap, and it's the property the UI
  // actually depends on.
  transactions.sort((a, b) => b.timestamp - a.timestamp);
  return transactions;
}

interface EtherscanEnvelope {
  status: string;
  message: string;
  result: unknown;
}

function isEtherscanEnvelope(value: unknown): value is EtherscanEnvelope {
  return (
    typeof value === "object" &&
    value !== null &&
    "status" in value &&
    "message" in value &&
    "result" in value &&
    typeof (value as { status: unknown }).status === "string" &&
    typeof (value as { message: unknown }).message === "string"
  );
}

/**
 * A raw `txlist` result-array entry has many more fields than this app
 * uses (gas, nonce, input data, ...); only what's actually displayed is
 * validated and kept, so a shape change in the fields we ignore can't break
 * this.
 */
function parseTransaction(raw: unknown): SepoliaTransaction {
  if (typeof raw !== "object" || raw === null) {
    throw new EtherscanApiError("Etherscan returned a malformed transaction entry.");
  }
  const entry = raw as Record<string, unknown>;
  const hash = entry.hash;
  const from = entry.from;
  const to = entry.to;
  const value = entry.value;
  const timeStamp = entry.timeStamp;
  const isError = entry.isError;

  if (
    typeof hash !== "string" ||
    typeof from !== "string" ||
    typeof to !== "string" ||
    typeof value !== "string" ||
    typeof timeStamp !== "string"
  ) {
    throw new EtherscanApiError("Etherscan returned a malformed transaction entry.");
  }

  return {
    hash: hash as `0x${string}`,
    from: from as Address,
    // Etherscan reports a contract-creation transaction's `to` as "".
    to: to === "" ? null : (to as Address),
    valueWei: BigInt(value),
    timestamp: Number(timeStamp),
    failed: isError === "1",
  };
}

/** The public block-explorer page for a transaction, for independent verification. */
export function sepoliaExplorerTxUrl(hash: string): string {
  return `https://sepolia.etherscan.io/tx/${hash}`;
}
