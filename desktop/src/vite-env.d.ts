/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * Etherscan API key used for the read-only Sepolia transaction-history
   * fetch (see etherscan.ts). Free tier, obtained by signing up at
   * etherscan.io — see that file's doc comment for why a key is
   * unavoidable here (Etherscan's V2 API rejects every call without one,
   * confirmed 2026-08-20 against the live endpoint; there is no working
   * keyless/demo access left). Left unset in this repo; set it in a local
   * `.env` file (gitignored) to enable transaction history.
   */
  readonly VITE_ETHERSCAN_API_KEY?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
