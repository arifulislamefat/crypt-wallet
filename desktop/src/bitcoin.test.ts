import { afterEach, describe, expect, it, vi } from "vitest";
import {
  BITCOIN_ESPLORA_API_BASE,
  BitcoinApiError,
  fetchBitcoinBalanceSats,
  fetchBitcoinUtxos,
  formatSatsAsBtc,
} from "./bitcoin";

/**
 * `fetchBitcoinBalanceSats` is the one function in this module that touches
 * the network, so it's the one worth mocking `fetch` for — every other case
 * here (formatting) is pure and needs no mock at all.
 */
function mockFetchOnce(response: unknown, ok = true, status = 200) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok,
      status,
      json: () => Promise.resolve(response),
    }),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("fetchBitcoinBalanceSats", () => {
  it("computes a confirmed balance as funded minus spent", async () => {
    mockFetchOnce({
      chain_stats: { funded_txo_sum: 1_656_598_294, spent_txo_sum: 1_287_005_839 },
      mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0 },
    });
    const sats = await fetchBitcoinBalanceSats("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh");
    expect(sats).toBe(369_592_455n);
  });

  it("returns zero for a never-funded address", async () => {
    mockFetchOnce({
      chain_stats: { funded_txo_sum: 0, spent_txo_sum: 0 },
      mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0 },
    });
    const sats = await fetchBitcoinBalanceSats("bc1qlnestms492pa6t0pe5q279zmnhptnq5p4rx9xp");
    expect(sats).toBe(0n);
  });

  it("ignores mempool_stats -- only the confirmed chain balance is returned", async () => {
    mockFetchOnce({
      chain_stats: { funded_txo_sum: 1_000, spent_txo_sum: 0 },
      mempool_stats: { funded_txo_sum: 500_000, spent_txo_sum: 0 },
    });
    const sats = await fetchBitcoinBalanceSats("addr");
    expect(sats).toBe(1_000n);
  });

  it("requests the verified Esplora endpoint with the address in the path", async () => {
    mockFetchOnce({ chain_stats: { funded_txo_sum: 0, spent_txo_sum: 0 }, mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0 } });
    await fetchBitcoinBalanceSats("bc1qsomeaddress");

    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe(`${BITCOIN_ESPLORA_API_BASE}/address/bc1qsomeaddress`);
  });

  it("rejects with BitcoinApiError on a non-OK HTTP status", async () => {
    mockFetchOnce({}, false, 503);
    await expect(fetchBitcoinBalanceSats("x")).rejects.toThrow(BitcoinApiError);
  });

  it("rejects with BitcoinApiError on a malformed response missing chain_stats", async () => {
    mockFetchOnce({ mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0 } });
    await expect(fetchBitcoinBalanceSats("x")).rejects.toThrow(BitcoinApiError);
  });
});

describe("fetchBitcoinUtxos", () => {
  it("maps each Esplora UTXO to txid/vout/valueSats", async () => {
    mockFetchOnce([
      {
        txid: "48a5930b4e81fc4606c35495043567c1a7eeec6a24224f90a7a2bceb0bd645b0",
        vout: 0,
        status: { confirmed: true, block_height: 912728 },
        value: 6330,
      },
      {
        txid: "21f2930ade9ea77dfeeaa97326a51a7e6992bdf0bd001ed6d2a826ea4820e21a",
        vout: 1,
        status: { confirmed: true, block_height: 963298 },
        value: 14076,
      },
    ]);
    const utxos = await fetchBitcoinUtxos("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh");
    expect(utxos).toEqual([
      { txid: "48a5930b4e81fc4606c35495043567c1a7eeec6a24224f90a7a2bceb0bd645b0", vout: 0, valueSats: 6330n },
      { txid: "21f2930ade9ea77dfeeaa97326a51a7e6992bdf0bd001ed6d2a826ea4820e21a", vout: 1, valueSats: 14076n },
    ]);
  });

  it("returns an empty array for a never-funded address", async () => {
    mockFetchOnce([]);
    const utxos = await fetchBitcoinUtxos("bc1qlnestms492pa6t0pe5q279zmnhptnq5p4rx9xp");
    expect(utxos).toEqual([]);
  });

  it("excludes unconfirmed UTXOs", async () => {
    mockFetchOnce([
      { txid: "confirmed-one", vout: 0, status: { confirmed: true }, value: 1_000 },
      { txid: "unconfirmed-one", vout: 0, status: { confirmed: false }, value: 500_000 },
    ]);
    const utxos = await fetchBitcoinUtxos("addr");
    expect(utxos).toEqual([{ txid: "confirmed-one", vout: 0, valueSats: 1_000n }]);
  });

  it("requests the verified Esplora UTXO endpoint with the address in the path", async () => {
    mockFetchOnce([]);
    await fetchBitcoinUtxos("bc1qsomeaddress");

    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe(`${BITCOIN_ESPLORA_API_BASE}/address/bc1qsomeaddress/utxo`);
  });

  it("rejects with BitcoinApiError on a non-OK HTTP status", async () => {
    mockFetchOnce([], false, 503);
    await expect(fetchBitcoinUtxos("x")).rejects.toThrow(BitcoinApiError);
  });

  it("rejects with BitcoinApiError when the response is not an array", async () => {
    mockFetchOnce({ not: "an array" });
    await expect(fetchBitcoinUtxos("x")).rejects.toThrow(BitcoinApiError);
  });
});

describe("formatSatsAsBtc", () => {
  it("formats a whole-BTC amount with no trailing fraction", () => {
    expect(formatSatsAsBtc(100_000_000n)).toBe("1");
  });

  it("formats a fractional amount at full 8-decimal precision", () => {
    expect(formatSatsAsBtc(150_000_000n)).toBe("1.5");
  });

  it("formats the smallest unit (1 satoshi)", () => {
    expect(formatSatsAsBtc(1n)).toBe("0.00000001");
  });

  it("formats zero", () => {
    expect(formatSatsAsBtc(0n)).toBe("0");
  });
});
