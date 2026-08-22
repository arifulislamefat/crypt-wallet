/// <reference types="vite/client" />

// No app-specific ImportMetaEnv keys as of 2026-08-22: the one that used to
// live here, VITE_ETHERSCAN_API_KEY, was removed when the Etherscan API key
// moved to the Rust backend (desktop/src-tauri/.env, ETHERSCAN_API_KEY) --
// see etherscan.ts's own doc comment for why a Vite build-time env var was
// the wrong place for it (it shipped inlined in the built JS bundle).
