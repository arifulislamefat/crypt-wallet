import { formatUnits } from "viem";

/**
 * Bitcoin mainnet balance and UTXO fetching — view-only, mirroring
 * `solana.ts`'s role for the Solana chain family: this module's only job is
 * turning a bech32 address into displayable BTC data (a summed balance, and
 * the individual unspent outputs behind it). No UTXO *selection*, no
 * transaction construction, no signing — that's deliberately a later,
 * separate phase (see `crypto/src/bitcoin.rs`'s module doc comment for why
 * derivation and signing are staged separately for this chain).
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
