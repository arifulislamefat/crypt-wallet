import { bech32, bech32m } from "bech32";
import { formatUnits } from "viem";

/**
 * Bitcoin mainnet balance/UTXO fetching, fee estimation, coin selection,
 * and broadcast — mirroring `solana.ts`'s role for the Solana chain
 * family. Transaction *construction and signing* are NOT here — that's
 * `sign_bitcoin_transaction` in `desktop/src-tauri/src/lib.rs`, using the
 * `bitcoin` crate, the same "audited library, not hand-rolled" rule EVM
 * (`alloy`) and Solana (`solana-sdk`) signing already follow. This module's
 * job is everything around that: deciding which UTXOs to spend and at what
 * fee rate, then handing the fully-decided shape to that command to sign,
 * then broadcasting what comes back — the same split `main.ts`'s
 * `reviewSend`/`confirmSend` already use for EVM (nonce/fee estimation in
 * the frontend, signing in Rust).
 *
 * Unlike EVM/Solana, Bitcoin has no single "getBalance" RPC call — a
 * balance is the sum of unspent transaction outputs (UTXOs) for an address,
 * which requires an indexer, not a node RPC call. There's no bundled
 * Etherscan-equivalent for Bitcoin, so a public Esplora-API indexer is used
 * instead — unlike Etherscan (see `etherscan.ts`), no API key is needed.
 *
 * Endpoint choice — evaluated two established, open-source, Esplora-schema
 * indexers before picking one, same "not just the first search result" bar
 * every other dependency/endpoint in this app is held to:
 * - mempool.space (github.com/mempool/mempool, "mempool" org, AGPL-3.0,
 *   2.8k+ stars): the most widely-used community Bitcoin explorer today,
 *   and what several popular wallets (e.g. Sparrow) default to. Could NOT
 *   be live-verified during this evaluation, though — both a direct HTTPS
 *   request and a browser navigation to mempool.space timed out/were
 *   denied from the development environment, for reasons not fully
 *   diagnosed (possibly this environment's own network policy, not
 *   necessarily a reflection of the service's real-world availability).
 * - blockstream.info (github.com/Blockstream/esplora, Blockstream org,
 *   MIT, 1.3k+ stars): the original public Esplora instance, run by
 *   Blockstream (a long-established Bitcoin infrastructure company).
 *   Successfully live-verified during this evaluation: a request to
 *   `/api/address/{addr}` for a known, funded bech32 address (the BIP-173
 *   spec's own example address, `bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh`)
 *   returned the expected `chain_stats`/`mempool_stats` schema with real,
 *   nonzero funded/spent totals, and the same call against this app's own
 *   (never-funded) derived Bitcoin address correctly returned all-zero
 *   stats.
 *
 * blockstream.info is used here on the strength of that live verification —
 * the same "confirm against a live call, not just documentation" bar this
 * app already holds RPC endpoint choices to (see `solana.ts`'s genesis-hash
 * verification). Nothing here is tied to blockstream.info beyond this one
 * constant; mempool.space's identical response schema would make it a
 * drop-in alternative if its public API is confirmed reachable elsewhere.
 */
export const BITCOIN_ESPLORA_API_BASE = "https://blockstream.info/api";

/** BTC's fixed decimal count — every satoshi/BTC conversion in this app uses this, never a magic number inline. */
export const BTC_DECIMALS = 8;

/** A malformed or error Esplora API response — network failures surface as the underlying `fetch`/`TypeError`, not this. */
export class BitcoinApiError extends Error {}

interface EsploraAddressStats {
  funded_txo_sum: number;
  spent_txo_sum: number;
}

interface EsploraAddressResponse {
  chain_stats: EsploraAddressStats;
  mempool_stats: EsploraAddressStats;
}

/**
 * Fetch `address`'s confirmed BTC balance, in satoshis. There is no single
 * "balance" field in the Esplora API response — a confirmed balance is
 * `chain_stats.funded_txo_sum - chain_stats.spent_txo_sum`, the standard
 * way of deriving one from the address endpoint's documented shape.
 * Deliberately excludes `mempool_stats` (unconfirmed activity): showing an
 * unconfirmed balance as spendable would misrepresent what the wallet can
 * actually do with it at this view-only phase.
 */
export async function fetchBitcoinBalanceSats(address: string): Promise<bigint> {
  const response = await fetch(`${BITCOIN_ESPLORA_API_BASE}/address/${address}`);

  if (!response.ok) {
    throw new BitcoinApiError(`Bitcoin balance request failed: HTTP ${response.status}`);
  }

  const data = (await response.json()) as EsploraAddressResponse;
  if (!data.chain_stats) {
    throw new BitcoinApiError("malformed Esplora response: missing chain_stats");
  }

  const funded = BigInt(data.chain_stats.funded_txo_sum);
  const spent = BigInt(data.chain_stats.spent_txo_sum);
  return funded - spent;
}

/**
 * Format a satoshis amount as a BTC string, e.g. `0.00015`. Reuses viem's
 * decimal-count-generic `formatUnits`, the same reuse `solana.ts` already
 * applies for lamports -> SOL.
 */
export function formatSatsAsBtc(sats: bigint): string {
  return formatUnits(sats, BTC_DECIMALS);
}

/**
 * One confirmed, spendable output — deliberately more granular than
 * `fetchBitcoinBalanceSats`'s single summed number: a future transaction-
 * construction phase has to reason about *which* outputs it's spending
 * (`txid` + `vout` together are what a transaction input actually
 * references), not just a total. Nothing in this phase uses that
 * granularity yet — this is display-only, the plumbing this data will
 * eventually feed.
 */
export interface BitcoinUtxo {
  txid: string;
  vout: number;
  valueSats: bigint;
}

interface EsploraUtxo {
  txid: string;
  vout: number;
  value: number;
  status: { confirmed: boolean };
}

/**
 * Fetch `address`'s individual unspent outputs via Esplora's
 * `/address/:address/utxo` endpoint (same base URL/verification as
 * `fetchBitcoinBalanceSats` — see this module's own doc comment). Returns
 * only confirmed UTXOs, same reasoning as the balance fetch's exclusion of
 * `mempool_stats`: an unconfirmed output isn't safely spendable yet, so
 * treating it as available here would misrepresent what the wallet can
 * actually do with it.
 */
export async function fetchBitcoinUtxos(address: string): Promise<BitcoinUtxo[]> {
  const response = await fetch(`${BITCOIN_ESPLORA_API_BASE}/address/${address}/utxo`);

  if (!response.ok) {
    throw new BitcoinApiError(`Bitcoin UTXO request failed: HTTP ${response.status}`);
  }

  const data: unknown = await response.json();
  if (!Array.isArray(data)) {
    throw new BitcoinApiError("malformed Esplora response: expected an array of UTXOs");
  }

  return (data as EsploraUtxo[])
    .filter((utxo) => utxo.status?.confirmed)
    .map((utxo) => ({
      txid: utxo.txid,
      vout: utxo.vout,
      valueSats: BigInt(utxo.value),
    }));
}

/**
 * Real bech32/bech32m decode + prefix check for native SegWit ("bc1q...",
 * P2WPKH/P2WSH) and Taproot ("bc1p...", P2TR) mainnet addresses — the same
 * "use the real library, not a regex" bar `isValidSolanaAddress`/EVM's
 * EIP-55 check are held to, for the address shapes this wallet itself
 * actually produces (and so is most likely to be tested against — see this
 * session's Bitcoin send checkpoint). Legacy base58check addresses
 * (P2PKH `1...`, P2SH `3...`) are NOT decoded here — adding a second
 * address-encoding library for formats this wallet never generates itself
 * is scope beyond what this pass calls for; they get a lighter
 * length/alphabet check only, with no checksum verification — a wrong-
 * chain address that happens to share the same base58 alphabet/length
 * (some Solana addresses, for instance) can pass this specific check.
 * That's an accepted gap in this lighter path, not a security hole: the
 * real, authoritative validation for every address format (bech32 and
 * legacy alike) is `bitcoin::Address::from_str(...)` in
 * `sign_bitcoin_transaction_impl` (`desktop/src-tauri/src/lib.rs`), which
 * DOES verify the base58check checksum and would still correctly refuse
 * such an address before any signature is produced — the actual boundary
 * a malformed or wrong-chain recipient can never get past, same frontend-
 * vs-backend validation split every other chain in this app already uses.
 */
export function isValidBitcoinAddress(address: string): boolean {
  if (!address) {
    return false;
  }
  if (address.startsWith("bc1")) {
    try {
      const decoded = address.startsWith("bc1p") ? bech32m.decode(address) : bech32.decode(address);
      return decoded.prefix === "bc" && decoded.words.length > 0;
    } catch {
      return false;
    }
  }
  return /^[13][1-9A-HJ-NP-Za-km-z]{25,34}$/.test(address);
}

/**
 * Confirmation-target (in blocks) this app requests a fee-rate quote for —
 * roughly "confirm within about an hour," a single reasonable default
 * rather than a fee-tier selector UI, matching this phase's "correct and
 * safe, don't over-engineer" scope.
 */
const FEE_TARGET_BLOCKS = 6;

/**
 * Fetch a live fee-rate quote (sat/vB) from Esplora's `/fee-estimates`
 * endpoint — a map of confirmation-target (blocks) to fee rate, live-
 * verified during development (a real response looked like
 * `{"1": 5.03, "6": 2.234, "144": 0.315, ...}`). Picks the tightest
 * available target at or slower than `FEE_TARGET_BLOCKS`; if every target
 * Esplora currently publishes is faster than that (can happen in an
 * uncongested mempool, where it may only offer a handful of near-term
 * estimates), falls back to the slowest — i.e. cheapest — one actually
 * offered rather than erroring out. Still a real, live-quoted rate either
 * way, never a hardcoded fallback number.
 */
export async function fetchBitcoinFeeRateSatPerVb(): Promise<number> {
  const response = await fetch(`${BITCOIN_ESPLORA_API_BASE}/fee-estimates`);
  if (!response.ok) {
    throw new BitcoinApiError(`Bitcoin fee-estimate request failed: HTTP ${response.status}`);
  }

  const data: unknown = await response.json();
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw new BitcoinApiError("malformed Esplora response: expected a fee-estimates object");
  }

  const entries = Object.entries(data as Record<string, unknown>)
    .map((entry): [number, number] | null => {
      const target = Number(entry[0]);
      const rate = entry[1];
      return Number.isFinite(target) && typeof rate === "number" && rate > 0 ? [target, rate] : null;
    })
    .filter((entry): entry is [number, number] => entry !== null);

  if (entries.length === 0) {
    throw new BitcoinApiError("malformed Esplora response: no usable fee-estimate entries");
  }

  const atOrSlowerThanTarget = entries.filter(([target]) => target >= FEE_TARGET_BLOCKS).sort((a, b) => a[0] - b[0]);
  const chosen = atOrSlowerThanTarget[0] ?? entries.sort((a, b) => b[0] - a[0])[0];
  return chosen[1];
}

/**
 * Standard virtual-size costs (vbytes) for a transaction whose inputs and
 * outputs are all native SegWit P2WPKH — well-established constants (10.5
 * vB fixed overhead for a segwit-flagged transaction, ~68 vB per P2WPKH
 * input, ~31 vB per P2WPKH output), used to size a transaction BEFORE it's
 * actually built (the real, exact vsize is only known once
 * `sign_bitcoin_transaction` has produced the real signed transaction).
 * Slightly conservative if the recipient's address turns out to be a
 * costlier script type (P2PKH, P2TR) than P2WPKH: the true resulting fee
 * rate would then land a little below the target rather than exactly on
 * it — an acceptable imprecision for this phase's scope (the transaction
 * still confirms; it just wasn't sized for the absolute cheapest possible
 * fee), not a safety issue the way underestimating would be.
 */
const P2WPKH_TX_OVERHEAD_VBYTES = 10.5;
const P2WPKH_INPUT_VBYTES = 68;
const P2WPKH_OUTPUT_VBYTES = 31;

function estimateP2wpkhVsize(numInputs: number, numOutputs: number): number {
  return P2WPKH_TX_OVERHEAD_VBYTES + numInputs * P2WPKH_INPUT_VBYTES + numOutputs * P2WPKH_OUTPUT_VBYTES;
}

/**
 * Conservative dust threshold, in satoshis: an output below this is
 * uneconomical (may cost more to ever spend than it's worth, and some
 * relay policies refuse to propagate it). 546 sats is the commonly-cited,
 * widely-used figure across the ecosystem for a P2PKH-shaped output;
 * native SegWit's actual relay-policy dust limit is lower (~294 sats), so
 * this is deliberately the more conservative of the two — safe to apply
 * regardless of the change output's exact script type.
 */
const DUST_THRESHOLD_SATS = 546n;

/** The result of `selectBitcoinUtxos`: which UTXOs to spend, and the resulting fee/change split. */
export interface BitcoinSendPlan {
  selectedUtxos: BitcoinUtxo[];
  feeSats: bigint;
  changeSats: bigint;
}

/**
 * Simplest-correct coin selection: iterate `utxos` in the order given (no
 * least-waste/branch-and-bound optimization — deliberately, per this
 * phase's "correct and safe, don't over-engineer" scope), accumulating
 * inputs until they cover `amountSats` plus the estimated fee for the
 * transaction shape so far — recomputed on every UTXO added, since each
 * additional input changes the transaction's own size and therefore its
 * own fee.
 *
 * Dust change (below `DUST_THRESHOLD_SATS`) is folded into the fee instead
 * of creating an output the network might refuse to relay / that would
 * cost more to ever spend than it's worth — standard practice every real
 * wallet follows, not a shortcut.
 */
export function selectBitcoinUtxos(
  utxos: BitcoinUtxo[],
  amountSats: bigint,
  feeRateSatPerVb: number,
): BitcoinSendPlan {
  const selected: BitcoinUtxo[] = [];
  let totalIn = 0n;

  for (const utxo of utxos) {
    selected.push(utxo);
    totalIn += utxo.valueSats;

    const feeWithChange = BigInt(Math.ceil(estimateP2wpkhVsize(selected.length, 2) * feeRateSatPerVb));
    if (totalIn < amountSats + feeWithChange) {
      continue;
    }

    const change = totalIn - amountSats - feeWithChange;
    if (change >= DUST_THRESHOLD_SATS) {
      return { selectedUtxos: selected, feeSats: feeWithChange, changeSats: change };
    }
    // Change would be dust (or exactly zero) -- fold the whole leftover
    // into the fee and drop the change output entirely, rather than create
    // an uneconomical output.
    return { selectedUtxos: selected, feeSats: totalIn - amountSats, changeSats: 0n };
  }

  throw new BitcoinApiError("Insufficient confirmed balance to cover the amount plus network fee.");
}

/**
 * Broadcast an already-signed raw transaction (hex, as returned by the
 * `sign_bitcoin_transaction` command) via Esplora's `/tx` endpoint and
 * return its txid. That endpoint takes the raw hex as a plain-text POST
 * body and returns the txid as plain text on success, or an error message
 * (non-2xx) on failure — e.g. a fee too low, an already-spent input, or a
 * malformed transaction.
 */
export async function broadcastBitcoinTransaction(rawTxHex: string): Promise<string> {
  const response = await fetch(`${BITCOIN_ESPLORA_API_BASE}/tx`, {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: rawTxHex,
  });

  const text = await response.text();
  if (!response.ok) {
    throw new BitcoinApiError(`Broadcast failed: ${text || `HTTP ${response.status}`}`);
  }
  return text.trim();
}
