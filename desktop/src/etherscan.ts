import { invoke } from "@tauri-apps/api/core";
import type { Address } from "viem";

/**
 * Read-only transaction history for any network this app supports, via
 * Etherscan's V2 API — unified across chains through the `chainid` query
 * param (see `fetchEtherscanList`), not a separate host per network.
 *
 * Independent of everything in `main.ts`'s secret-handling flow, same as
 * `networks.ts` — this module only ever moves an address (public) out and a
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
 * 100,000 calls/day (docs.etherscan.io/rate-limits, checked same day). One
 * key works across every chain the V2 API supports — the same key backs
 * both networks this app knows about, nothing per-network to configure.
 *
 * POLICY HISTORY: through 2026-08-22 the key was read here directly, from
 * `VITE_ETHERSCAN_API_KEY` (a Vite build-time env var) — a real problem,
 * confirmed by inspecting a built app bundle: Vite inlines
 * `import.meta.env.VITE_*` values at build time, so the key shipped in
 * plaintext inside the built JS (`desktop/dist/assets/*.js`), readable by
 * anyone who inspected a shipped app's webview resources. Fixed by moving
 * the actual HTTP call to Rust (`fetch_etherscan_list` in
 * `desktop/src-tauri/src/lib.rs`, key read from `ETHERSCAN_API_KEY` in
 * `desktop/src-tauri/.env`, loaded at runtime, never compiled into any
 * artifact) — the key now never crosses into this file, or this process, at
 * all. `fetchTransactions`/`fetchTokenTransfers` still fail with a clear,
 * distinguishable message when it's unset backend-side (see
 * `EtherscanConfigError`), same as before this fix.
 *
 * ## Two endpoints, two different views of the same activity
 *
 * `txlist` (module=account, action=txlist) covers plain transactions: ETH
 * value transfers, and any contract call this wallet's address itself sent
 * (including an ERC-20 `transfer()` call — but only as a 0-ETH call to a
 * contract, with no token details). It does NOT include a token transfer
 * this wallet only *received*: an incoming `transfer()` is a transaction
 * between two OTHER addresses (the sender and the token contract), so
 * `txlist` filtered by our address never surfaces it at all.
 *
 * `tokentx` (module=account, action=tokentx) is indexed from the token
 * contracts' own `Transfer` event logs, not raw transactions — it covers
 * every ERC-20 transfer where our address is either side, sent or
 * received, and comes with the token's symbol/decimals already attached
 * (Etherscan's own indexed read of the contract, not re-verified against a
 * live `eth_call` here — see `main.ts`'s `renderTokenTransferItem`, which
 * prefers the app's own contract-read `tokenMetadataCache` over these
 * fields when it's available, and falls back to them otherwise). It does
 * NOT include a *failed* token-transfer transaction: a reverted call emits
 * no event, so there's nothing for `tokentx` to index — that case only
 * shows up via `txlist`, correctly marked `isError`.
 *
 * `main.ts`'s `fetchTxHistory` fetches both and merges them, preferring
 * `tokentx`'s richer data for any hash it covers and falling back to
 * `txlist` for everything else (plain ETH activity, and the failed-token-
 * transfer edge case above).
 *
 * The API base URL itself (`https://api.etherscan.io/v2/api`) now lives
 * backend-side, in `ETHERSCAN_API_BASE_URL` (`desktop/src-tauri/src/lib.rs`)
 * — see `fetchEtherscanList`'s own doc comment for why the actual HTTP call
 * moved there.
 */

/**
 * Exact copy, kept in sync by hand, of the message
 * `fetch_etherscan_list` (`desktop/src-tauri/src/lib.rs`) returns when
 * `ETHERSCAN_API_KEY` isn't set — the same "match the backend's error
 * string" pattern `SESSION_LOCKED_ERROR` uses in `main.ts`, needed here to
 * distinguish a config problem from a genuine network/API failure (see
 * `fetchEtherscanList`'s catch block). The two need different messages and,
 * for the caller, different next steps (fix a `.env` file vs. "try again
 * later").
 */
const ETHERSCAN_CONFIG_ERROR_MESSAGE =
  "No Etherscan API key is configured (set ETHERSCAN_API_KEY in desktop/src-tauri/.env).";

/** See `ETHERSCAN_CONFIG_ERROR_MESSAGE`'s own doc comment for what distinguishes this from `EtherscanApiError`. */
export class EtherscanConfigError extends Error {}

/** A real Etherscan request failed — network error, HTTP error, or an API-level error response. */
export class EtherscanApiError extends Error {}

export interface EthTransaction {
  hash: `0x${string}`;
  from: Address;
  /** `null` for a contract-creation transaction, which has no `to`. */
  to: Address | null;
  valueWei: bigint;
  /** Unix seconds. */
  timestamp: number;
  /** `false` also covers the small share of very old pre-Byzantium txs Etherscan can't classify — treated as success, matching Etherscan's own website display. */
  failed: boolean;
  /**
   * Raw calldata, `"0x"` for a plain value transfer. Kept so the history
   * view can detect and label an ERC-20 `transfer()` call this endpoint
   * alone would otherwise show as a plain ETH send of 0 ETH — relevant now
   * only for the failed-token-transfer edge case `tokentx` can't cover (see
   * this module's top-level doc comment), since a successful one is
   * rendered from `fetchTokenTransfers` instead.
   */
  input: `0x${string}`;
}

/** One ERC-20 `Transfer` event involving our address, from the `tokentx` endpoint. */
export interface TokenTransferEvent {
  hash: `0x${string}`;
  from: Address;
  to: Address;
  tokenAddress: Address;
  /** Etherscan's own indexed value — see this module's top-level doc comment on when this is, and isn't, re-verified. */
  tokenSymbol: string;
  /** Etherscan's own indexed value — see this module's top-level doc comment on when this is, and isn't, re-verified. */
  tokenDecimals: number;
  /** Raw on-chain amount, in the token's smallest unit. */
  amountRaw: bigint;
  /** Unix seconds. */
  timestamp: number;
}

/**
 * Fetch `address`'s transaction list on the chain identified by `chainId`
 * (module=account, action=txlist), newest first.
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
export async function fetchTransactions(
  chainId: number,
  address: Address,
): Promise<EthTransaction[]> {
  const raw = await fetchEtherscanList(chainId, "txlist", address);
  const transactions = raw.map(parseTransaction);
  // Newest first is also requested via `sort=desc`, but sorted again here
  // rather than trusted blind — cheap, and it's the property the UI
  // actually depends on.
  transactions.sort((a, b) => b.timestamp - a.timestamp);
  return transactions;
}

/**
 * Fetch every ERC-20 `Transfer` event involving `address` on the chain
 * identified by `chainId` (module=account, action=tokentx), sent or
 * received, newest first. Same two failure shapes and same "no history
 * isn't an error" handling as `fetchTransactions` — both endpoints share
 * `fetchEtherscanList` for exactly this reason.
 */
export async function fetchTokenTransfers(
  chainId: number,
  address: Address,
): Promise<TokenTransferEvent[]> {
  const raw = await fetchEtherscanList(chainId, "tokentx", address);
  const events = raw.map(parseTokenTransferEvent);
  events.sort((a, b) => b.timestamp - a.timestamp);
  return events;
}

/**
 * Shared plumbing for both endpoints: ask the backend
 * (`fetch_etherscan_list` in `desktop/src-tauri/src/lib.rs`) for the raw
 * response against `chainId` (Etherscan's V2 API is one host for every
 * chain it supports, selected entirely through this query param — not a
 * different subdomain per network the way the human-facing explorer
 * *website* is; see `NetworkConfig.explorerBaseUrl` in `networks.ts` for
 * that), then unwrap Etherscan's `{status, message, result}` envelope down
 * to the raw `result` array — everything both `txlist` and `tokentx` share
 * byte-for-byte except the `action` param and how each entry in `result` is
 * parsed, which stay in `fetchTransactions`/`fetchTokenTransfers` and their
 * respective per-entry parsers. The actual HTTP call, the API key, the
 * query-param construction, and the request timeout all live backend-side
 * now (see `fetch_etherscan_list`'s own doc comment for why) — this
 * function's job is just turning that raw JSON string into the array this
 * module's callers want, and translating the backend's plain-string error
 * (Tauri's `Result<_, String>` arrives here as a bare string, not an `Error`
 * object) into the right one of this module's two error classes.
 */
async function fetchEtherscanList(
  chainId: number,
  action: "txlist" | "tokentx",
  address: Address,
): Promise<unknown[]> {
  let raw: string;
  try {
    raw = await invoke<string>("fetch_etherscan_list", { chainId, action, address });
  } catch (error) {
    if (String(error) === ETHERSCAN_CONFIG_ERROR_MESSAGE) {
      throw new EtherscanConfigError(String(error));
    }
    throw new EtherscanApiError(String(error));
  }

  const body: unknown = JSON.parse(raw);
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

  return body.result;
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
 * A raw `txlist` result-array entry has many more fields than this app uses
 * (gas, nonce, method ID, ...); only what's actually displayed — including
 * `input`, needed to detect the failed-token-transfer edge case — is
 * validated and kept, so a shape change in the fields we still ignore can't
 * break this.
 */
function parseTransaction(raw: unknown): EthTransaction {
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
  const input = entry.input;

  if (
    typeof hash !== "string" ||
    typeof from !== "string" ||
    typeof to !== "string" ||
    typeof value !== "string" ||
    typeof timeStamp !== "string" ||
    typeof input !== "string"
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
    input: (input === "" ? "0x" : input) as `0x${string}`,
  };
}

/**
 * A raw `tokentx` result-array entry, similarly trimmed to only the fields
 * this app displays (contractAddress, value, tokenSymbol, tokenDecimal,
 * from/to/hash/timeStamp) out of the many `tokentx` also returns (gas,
 * nonce, confirmations, tokenName, ...).
 */
function parseTokenTransferEvent(raw: unknown): TokenTransferEvent {
  if (typeof raw !== "object" || raw === null) {
    throw new EtherscanApiError("Etherscan returned a malformed token-transfer entry.");
  }
  const entry = raw as Record<string, unknown>;
  const hash = entry.hash;
  const from = entry.from;
  const to = entry.to;
  const contractAddress = entry.contractAddress;
  const value = entry.value;
  const tokenSymbol = entry.tokenSymbol;
  const tokenDecimal = entry.tokenDecimal;
  const timeStamp = entry.timeStamp;

  if (
    typeof hash !== "string" ||
    typeof from !== "string" ||
    typeof to !== "string" ||
    typeof contractAddress !== "string" ||
    typeof value !== "string" ||
    typeof tokenSymbol !== "string" ||
    typeof tokenDecimal !== "string" ||
    typeof timeStamp !== "string"
  ) {
    throw new EtherscanApiError("Etherscan returned a malformed token-transfer entry.");
  }

  return {
    hash: hash as `0x${string}`,
    from: from as Address,
    to: to as Address,
    tokenAddress: contractAddress as Address,
    tokenSymbol,
    tokenDecimals: Number(tokenDecimal),
    amountRaw: BigInt(value),
    timestamp: Number(timeStamp),
  };
}

/** The public block-explorer page for a transaction on `explorerBaseUrl`'s network, for independent verification. */
export function explorerTxUrl(explorerBaseUrl: string, hash: string): string {
  return `${explorerBaseUrl}/tx/${hash}`;
}
