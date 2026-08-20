import { describe, expect, it } from "vitest";
import { formatUnits } from "viem";
import { parseUnitsStrict } from "./tokens";

/**
 * USDC's real, contract-read decimals value (verified live on-chain
 * 2026-08-20 — see the doc comment on `SEPOLIA_TOKENS` in tokens.ts) is 6,
 * not 18 like ETH. Every test in this file exists to catch the "classic
 * off-by-decimals bug" the send feature's spec called out by name: silently
 * treating a token amount as if it had the wrong number of decimals shows a
 * balance or a sent amount off by orders of magnitude — one of the most
 * dangerous, embarrassing classes of wallet bug there is.
 */
const USDC_DECIMALS = 6;

describe("parseUnitsStrict / formatUnits round trip at USDC's real decimals (6)", () => {
  it("converts a whole-number human amount to the correct raw units", () => {
    expect(parseUnitsStrict("100", USDC_DECIMALS)).toBe(100_000_000n);
  });

  it("converts a fractional human amount to the correct raw units", () => {
    expect(parseUnitsStrict("1.234567", USDC_DECIMALS)).toBe(1_234_567n);
  });

  it("converts the smallest representable unit (1 raw = 0.000001 USDC)", () => {
    expect(parseUnitsStrict("0.000001", USDC_DECIMALS)).toBe(1n);
  });

  it("round-trips human -> raw -> human without drift", () => {
    for (const human of ["0.000001", "1", "1.5", "1234.56", "99999.999999"]) {
      const raw = parseUnitsStrict(human, USDC_DECIMALS);
      expect(formatUnits(raw, USDC_DECIMALS)).toBe(human);
    }
  });

  it("formats a raw on-chain balance back to the correct human amount", () => {
    // The exact shape of what `fetchTokenBalance`'s `balance` field holds
    // and what `renderTokenRow` formats for display.
    expect(formatUnits(1_234_567n, USDC_DECIMALS)).toBe("1.234567");
  });

  it("rejects malformed input the same way parseEtherStrict does", () => {
    for (const bad of ["", "abc", "-1", "1.2.3", "1e10", "  1", "1 "]) {
      expect(() => parseUnitsStrict(bad, USDC_DECIMALS)).toThrow();
    }
  });

  it("the classic off-by-decimals bug: using 18 instead of USDC's real 6 is wrong by 10^12", () => {
    const raw = parseUnitsStrict("1.5", USDC_DECIMALS); // 1,500,000 raw units, correctly
    expect(raw).toBe(1_500_000n);

    // What formatting that SAME raw value would show if decimals were
    // wrongly hardcoded to 18 (ETH's value) instead of read from the
    // contract — this must NOT equal the correct human amount. If it ever
    // did, that would mean this test stopped being able to catch the bug
    // it exists to catch.
    const wronglyFormatted = formatUnits(raw, 18);
    const correctlyFormatted = formatUnits(raw, USDC_DECIMALS);
    expect(wronglyFormatted).not.toBe(correctlyFormatted);
    expect(correctlyFormatted).toBe("1.5");
    expect(wronglyFormatted).toBe("0.0000000000015");

    // Quantify it: off by exactly 10^(18-6) = 10^12, not some other wrong
    // amount -- pins down that this is specifically a decimals-power bug.
    const ratio = Number(correctlyFormatted) / Number(wronglyFormatted);
    expect(ratio).toBeCloseTo(1e12, 0);
  });

  it("the same bug in the other direction: using 6 instead of a hypothetical 18-decimal token's real value", () => {
    // Same raw integer, interpreted with the wrong (smaller) decimals count
    // shows an amount far too LARGE instead of far too small -- both
    // directions of this bug are real and both must be caught by always
    // using the contract-read value, never an assumption.
    const raw = 1_500_000n;
    expect(formatUnits(raw, 6)).toBe("1.5");
    expect(formatUnits(raw, 18)).not.toBe("1.5");
  });
});
