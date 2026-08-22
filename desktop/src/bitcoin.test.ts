import { afterEach, describe, expect, it, vi } from "vitest";
import {
  BITCOIN_ESPLORA_API_BASE,
  BitcoinApiError,
  broadcastBitcoinTransaction,
  fetchBitcoinBalanceSats,
  fetchBitcoinFeeRateSatPerVb,
  fetchBitcoinUtxos,
  formatSatsAsBtc,
  isValidBitcoinAddress,
  selectBitcoinUtxos,
  type BitcoinUtxo,
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

describe("isValidBitcoinAddress", () => {
  it("accepts this wallet's own real, derived native SegWit address", () => {
    expect(isValidBitcoinAddress("bc1qlnestms492pa6t0pe5q279zmnhptnq5p4rx9xp")).toBe(true);
  });

  it("accepts the BIP-173 spec's own example native SegWit address", () => {
    expect(isValidBitcoinAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")).toBe(true);
  });

  it("accepts a real Taproot (bech32m) address", () => {
    // A well-known, real mainnet Taproot address (BIP-350's own test vector).
    expect(isValidBitcoinAddress("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297")).toBe(true);
  });

  it("rejects the empty string", () => {
    expect(isValidBitcoinAddress("")).toBe(false);
  });

  it("rejects a bech32-shaped string with an invalid checksum", () => {
    expect(isValidBitcoinAddress("bc1qlnestms492pa6t0pe5q279zmnhptnq5p4rx9xq")).toBe(false);
  });

  it("rejects a string too short to be a real legacy address, even if base58-alphabet and correctly prefixed", () => {
    expect(isValidBitcoinAddress("1tooshort")).toBe(false);
  });

  it("rejects a legacy-shaped string containing a character outside the base58 alphabet", () => {
    // "0", "O", "I", "l" are excluded from base58 -- same class of typo this
    // check exists to catch even without a full checksum decode.
    expect(isValidBitcoinAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7Div0Na")).toBe(false);
  });

  it("accepts a well-formed-looking legacy P2PKH address on the light heuristic", () => {
    // The famous Genesis Block coinbase address -- real, well-known, legacy P2PKH.
    expect(isValidBitcoinAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")).toBe(true);
  });

  it("rejects a string that is neither bech32-prefixed nor legacy-shaped", () => {
    expect(isValidBitcoinAddress("not-a-bitcoin-address")).toBe(false);
  });
});

describe("fetchBitcoinFeeRateSatPerVb", () => {
  it("picks the entry at exactly the target confirmation block count when present", async () => {
    mockFetchOnce({ "1": 5.03, "6": 2.234, "144": 0.315 });
    expect(await fetchBitcoinFeeRateSatPerVb()).toBe(2.234);
  });

  it("picks the tightest target slower than the preferred one when the exact target is missing", async () => {
    mockFetchOnce({ "1": 5.03, "5": 3.0, "8": 1.5, "144": 0.315 });
    expect(await fetchBitcoinFeeRateSatPerVb()).toBe(1.5);
  });

  it("falls back to the slowest available target when every one is faster than preferred", async () => {
    mockFetchOnce({ "1": 5.03, "2": 4.0, "3": 3.5 });
    expect(await fetchBitcoinFeeRateSatPerVb()).toBe(3.5);
  });

  it("requests the verified Esplora fee-estimates endpoint", async () => {
    mockFetchOnce({ "6": 1.0 });
    await fetchBitcoinFeeRateSatPerVb();
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    expect(fetchMock.mock.calls[0][0]).toBe(`${BITCOIN_ESPLORA_API_BASE}/fee-estimates`);
  });

  it("rejects with BitcoinApiError on a non-OK HTTP status", async () => {
    mockFetchOnce({}, false, 503);
    await expect(fetchBitcoinFeeRateSatPerVb()).rejects.toThrow(BitcoinApiError);
  });

  it("rejects with BitcoinApiError on a malformed (non-object) response", async () => {
    mockFetchOnce([1, 2, 3]);
    await expect(fetchBitcoinFeeRateSatPerVb()).rejects.toThrow(BitcoinApiError);
  });

  it("rejects with BitcoinApiError when no entry is a usable positive number", async () => {
    mockFetchOnce({ "6": "not-a-number", "144": -1 });
    await expect(fetchBitcoinFeeRateSatPerVb()).rejects.toThrow(BitcoinApiError);
  });
});

describe("selectBitcoinUtxos", () => {
  function utxo(valueSats: number, vout = 0, txid = "t"): BitcoinUtxo {
    return { txid: `${txid}${vout}`, vout, valueSats: BigInt(valueSats) };
  }

  it("selects a single UTXO and returns real change when the leftover is well above dust", () => {
    const plan = selectBitcoinUtxos([utxo(100_000)], 50_000n, 1);
    expect(plan.selectedUtxos).toEqual([utxo(100_000)]);
    // vsize(1 in, 2 out) = 10.5 + 68 + 2*31 = 140.5 -> ceil = 141 sats at 1 sat/vB.
    expect(plan.feeSats).toBe(141n);
    expect(plan.changeSats).toBe(100_000n - 50_000n - 141n);
    expect(plan.changeSats).toBeGreaterThan(546n);
  });

  it("selects multiple UTXOs in order until the amount plus fee is covered", () => {
    const plan = selectBitcoinUtxos([utxo(10_000, 0), utxo(10_000, 1), utxo(100_000, 2)], 25_000n, 1);
    expect(plan.selectedUtxos).toEqual([utxo(10_000, 0), utxo(10_000, 1), utxo(100_000, 2)]);
  });

  it("folds dust-sized change into the fee instead of creating a dust output", () => {
    // 1 input of exactly amount + fee(1-out) + 100 sats of "change" that
    // would be well under the 546-sat dust threshold.
    const feeNoChange = Math.ceil((10.5 + 68 + 31) * 1); // vsize(1 in, 1 out) at 1 sat/vB
    const plan = selectBitcoinUtxos([utxo(50_000 + feeNoChange + 100)], 50_000n, 1);
    expect(plan.changeSats).toBe(0n);
    expect(plan.feeSats).toBe(BigInt(feeNoChange) + 100n);
  });

  it("throws BitcoinApiError when the available UTXOs can't cover the amount plus fee", () => {
    expect(() => selectBitcoinUtxos([utxo(1_000)], 50_000n, 1)).toThrow(BitcoinApiError);
  });

  it("throws BitcoinApiError for an empty UTXO set", () => {
    expect(() => selectBitcoinUtxos([], 1_000n, 1)).toThrow(BitcoinApiError);
  });
});

describe("broadcastBitcoinTransaction", () => {
  function mockFetchText(text: string, ok = true, status = 200) {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok, status, text: () => Promise.resolve(text) }),
    );
  }

  it("returns the trimmed txid on success", async () => {
    mockFetchText("abc123txid\n");
    expect(await broadcastBitcoinTransaction("deadbeef")).toBe("abc123txid");
  });

  it("posts the raw hex as a plain-text body to the verified broadcast endpoint", async () => {
    mockFetchText("txid");
    await broadcastBitcoinTransaction("deadbeef");
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(`${BITCOIN_ESPLORA_API_BASE}/tx`);
    expect(init.method).toBe("POST");
    expect(init.body).toBe("deadbeef");
  });

  it("rejects with BitcoinApiError, including the response body, on a non-OK status", async () => {
    mockFetchText("bad-txn-fee-too-low", false, 400);
    await expect(broadcastBitcoinTransaction("deadbeef")).rejects.toThrow(/bad-txn-fee-too-low/);
  });
});
