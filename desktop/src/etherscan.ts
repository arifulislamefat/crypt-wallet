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
 * The key is read from `VITE_ETHERSCAN_API_KEY` (a Vite build-time env var,
 * see `vite-env.d.ts` and the repo's `.env.example`) rather than hardcoded,
 * so swapping in a real key later — or rotating one — never touches this
 * file. `fetchTransactions` and `fetchTokenTransfers` both fail fast with a
 * clear message when it's unset, instead of sending a doomed request.
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
 */
const ETHERSCAN_API_BASE_URL = "https://api.etherscan.io/v2/api";

/**
 * Most recent entries to request per fetch, for either endpoint. This is a
 * read-only history view, not a full ledger export — 100 covers "what did I
 * just do" for a wallet this young without needing pagination UI yet.
 */
const MAX_RESULTS = 100;

/**
 * Bounded for the same reason as `RPC_TIMEOUT_MS` in networks.ts: an
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
 * Shared plumbing for both endpoints: build the request against `chainId`
 * (Etherscan's V2 API is one host for every chain it supports, selected
 * entirely through this query param — not a different subdomain per
 * network the way the human-facing explorer *website* is; see
 * `NetworkConfig.explorerBaseUrl` in `networks.ts` for that), enforce the
 * timeout, and unwrap Etherscan's `{status, message, result}` envelope down
 * to the raw `result` array — everything both `txlist` and `tokentx` share
 * byte-for-byte except the `action` param and how each entry in `result` is
 * parsed, which stay in `fetchTransactions`/`fetchTokenTransfers` and their
 * respective per-entry parsers.
 */
async function fetchEtherscanList(
  chainId: number,
  action: "txlist" | "tokentx",
  address: Address,
): Promise<unknown[]> {
  if (!hasEtherscanApiKey()) {
    throw new EtherscanConfigError(
      "No Etherscan API key is configured (set VITE_ETHERSCAN_API_KEY in .env).",
    );
  }

  const url = new URL(ETHERSCAN_API_BASE_URL);
  url.searchParams.set("chainid", String(chainId));
  url.searchParams.set("module", "account");
  url.searchParams.set("action", action);
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
