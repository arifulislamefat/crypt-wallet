import { afterEach, describe, expect, it, vi } from "vitest";
import {
  BASE_FEE_LAMPORTS_PER_SIGNATURE,
  SOLANA_MAINNET_RPC_URL,
  SolanaRpcError,
  confirmSolanaTransaction,
  fetchLatestBlockhash,
  fetchSolanaBalanceLamports,
  formatLamportsAsSol,
  isValidSolanaAddress,
  sendRawSolanaTransaction,
} from "./solana";

describe("isValidSolanaAddress", () => {
  it("accepts a real, known-valid 32-byte address (the System Program ID)", () => {
    expect(isValidSolanaAddress("11111111111111111111111111111111")).toBe(true);
  });

  it("accepts the addresses confirmed live on mainnet earlier this session", () => {
    expect(isValidSolanaAddress("GAfD4PcV6TogQXr8dKffdvnoQfrWRXDBZz1N6yyiBcnL")).toBe(true);
    expect(isValidSolanaAddress("FpxjtumdWSXRDALrHFgzL8b9Tg8mnGoQsExhD1H8eNsk")).toBe(true);
  });

  it("rejects the empty string", () => {
    expect(isValidSolanaAddress("")).toBe(false);
  });

  it("rejects a string containing characters outside the Base58 alphabet", () => {
    // "0", "O", "I", "l" are deliberately excluded from Base58 -- a common
    // typo/transcription source, and exactly the class of input a naive
    // "looks like an address" regex could miss.
    expect(isValidSolanaAddress("0Fpxjtumd0SXRDALrHFgzL8b9Tg8mnGoQsExhD1H8eNsk")).toBe(false);
  });

  it("rejects a well-formed Base58 string that decodes to the wrong byte length", () => {
    // Valid Base58, but far too short to be a 32-byte key.
    expect(isValidSolanaAddress("abc")).toBe(false);
    // An EVM address (also just characters, but the wrong alphabet/shape
    // entirely) must never be accepted as a Solana one.
    expect(isValidSolanaAddress("0x0000000000000000000000000000000000dEaD")).toBe(false);
  });
});

/**
 * `fetchSolanaBalanceLamports` is the one function in this module that
 * touches the network, so it's the one worth mocking `fetch` for — every
 * other case here (formatting) is pure and needs no mock at all.
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

describe("fetchSolanaBalanceLamports", () => {
  it("parses a well-formed getBalance response into lamports", async () => {
    mockFetchOnce({ jsonrpc: "2.0", id: 1, result: { context: { slot: 1 }, value: 1_500_000_000 } });
    const lamports = await fetchSolanaBalanceLamports("11111111111111111111111111111111");
    expect(lamports).toBe(1_500_000_000n);
  });

  it("posts to the verified mainnet RPC endpoint with the address as the sole param", async () => {
    mockFetchOnce({ jsonrpc: "2.0", id: 1, result: { context: { slot: 1 }, value: 0 } });
    await fetchSolanaBalanceLamports("SomeAddress111111111111111111111111111111");

    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(SOLANA_MAINNET_RPC_URL);
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body.method).toBe("getBalance");
    expect(body.params).toEqual(["SomeAddress111111111111111111111111111111"]);
  });

  it("rejects with SolanaRpcError on an RPC-level error response", async () => {
    mockFetchOnce({ jsonrpc: "2.0", id: 1, error: { code: -32602, message: "invalid param" } });
    await expect(fetchSolanaBalanceLamports("bad-address")).rejects.toThrow(SolanaRpcError);
  });

  it("rejects with SolanaRpcError on a non-OK HTTP status", async () => {
    mockFetchOnce({}, false, 503);
    await expect(fetchSolanaBalanceLamports("x")).rejects.toThrow(SolanaRpcError);
  });

  it("rejects with SolanaRpcError on a malformed response missing both result and error", async () => {
    mockFetchOnce({ jsonrpc: "2.0", id: 1 });
    await expect(fetchSolanaBalanceLamports("x")).rejects.toThrow(SolanaRpcError);
  });
});

describe("fetchLatestBlockhash", () => {
  it("extracts the blockhash string from a well-formed response", async () => {
    mockFetchOnce({
      jsonrpc: "2.0",
      id: 1,
      result: { context: { slot: 1 }, value: { blockhash: "SomeBlockhash1111111111111111111111111111", lastValidBlockHeight: 100 } },
    });
    const blockhash = await fetchLatestBlockhash();
    expect(blockhash).toBe("SomeBlockhash1111111111111111111111111111");
  });

  it("requests finalized commitment", async () => {
    mockFetchOnce({
      jsonrpc: "2.0",
      id: 1,
      result: { context: { slot: 1 }, value: { blockhash: "x", lastValidBlockHeight: 1 } },
    });
    await fetchLatestBlockhash();
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    const body = JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string);
    expect(body.method).toBe("getLatestBlockhash");
    expect(body.params).toEqual([{ commitment: "finalized" }]);
  });
});

describe("sendRawSolanaTransaction", () => {
  it("returns the signature from a well-formed sendTransaction response", async () => {
    mockFetchOnce({ jsonrpc: "2.0", id: 1, result: "SomeSignature111111111111111111111111111111111111111111111111111111111111" });
    const signature = await sendRawSolanaTransaction("base64-tx-bytes");
    expect(signature).toBe("SomeSignature111111111111111111111111111111111111111111111111111111111111");
  });

  it("posts the base64-encoded transaction with base64 encoding specified", async () => {
    mockFetchOnce({ jsonrpc: "2.0", id: 1, result: "sig" });
    await sendRawSolanaTransaction("base64-tx-bytes");
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    const body = JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string);
    expect(body.method).toBe("sendTransaction");
    expect(body.params[0]).toBe("base64-tx-bytes");
    expect(body.params[1]).toMatchObject({ encoding: "base64" });
  });

  it("rejects with SolanaRpcError when the RPC refuses the transaction", async () => {
    mockFetchOnce({ jsonrpc: "2.0", id: 1, error: { code: -32002, message: "Transaction simulation failed" } });
    await expect(sendRawSolanaTransaction("bad-tx")).rejects.toThrow(SolanaRpcError);
  });
});

describe("confirmSolanaTransaction", () => {
  it("returns 'confirmed' as soon as the status reports it, without waiting out the timeout", async () => {
    mockFetchOnce({
      jsonrpc: "2.0",
      id: 1,
      result: { context: { slot: 1 }, value: [{ err: null, confirmationStatus: "confirmed" }] },
    });
    const status = await confirmSolanaTransaction("sig", 60_000, 1);
    expect(status).toBe("confirmed");
  });

  it("returns 'failed' when the status reports a transaction error", async () => {
    mockFetchOnce({
      jsonrpc: "2.0",
      id: 1,
      result: { context: { slot: 1 }, value: [{ err: { InstructionError: [0, "Custom"] }, confirmationStatus: null }] },
    });
    const status = await confirmSolanaTransaction("sig", 60_000, 1);
    expect(status).toBe("failed");
  });

  it("returns 'not_found' once the timeout elapses with no terminal status", async () => {
    mockFetchOnce({ jsonrpc: "2.0", id: 1, result: { context: { slot: 1 }, value: [null] } });
    const status = await confirmSolanaTransaction("sig", 5, 2);
    expect(status).toBe("not_found");
  });
});

describe("BASE_FEE_LAMPORTS_PER_SIGNATURE", () => {
  it("is Solana's documented fixed base fee: 5000 lamports", () => {
    expect(BASE_FEE_LAMPORTS_PER_SIGNATURE).toBe(5_000n);
  });
});

describe("formatLamportsAsSol", () => {
  it("formats a whole-SOL amount with no trailing fraction", () => {
    expect(formatLamportsAsSol(1_000_000_000n)).toBe("1");
  });

  it("formats a fractional amount at full 9-decimal precision", () => {
    expect(formatLamportsAsSol(1_500_000_000n)).toBe("1.5");
  });

  it("formats the smallest unit (1 lamport)", () => {
    expect(formatLamportsAsSol(1n)).toBe("0.000000001");
  });

  it("formats zero", () => {
    expect(formatLamportsAsSol(0n)).toBe("0");
  });
});
