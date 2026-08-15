#[cfg(debug_assertions)]
use cryptwallet_crypto::{EvmAccountKey, SecretMnemonic, WordCount};
#[cfg(debug_assertions)]
use cryptwallet_vault::{KdfParams, SealedVault};

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

/// DIAGNOSTIC ONLY — proves `cryptwallet-crypto` and `cryptwallet-vault` are
/// actually linked into the app and working, exercised across the Tauri IPC
/// boundary. MUST be removed before any real release; this is scaffolding
/// to verify crate wiring, not a real feature.
///
/// Gated behind `debug_assertions` so it is physically absent from release
/// builds — not just unregistered, but not compiled into the binary at all.
///
/// The mnemonic and seed generated here never leave this function and are
/// never stored or logged — only the derived (public) address is returned.
/// Both are dropped (and zeroized, per `crypto`'s own `ZeroizeOnDrop`
/// guarantees) at the end of this function's scope.
#[cfg(debug_assertions)]
#[tauri::command]
fn core_health_check() -> String {
    let crypto_summary = match SecretMnemonic::generate(WordCount::Twelve) {
        Ok(mnemonic) => {
            let seed = mnemonic.to_seed("");
            match EvmAccountKey::derive(&seed, 0) {
                Ok(account) => format!("crypto: ok (derived {})", account.address()),
                Err(_) => "crypto: FAILED".to_string(),
            }
        }
        Err(_) => "crypto: FAILED".to_string(),
    };

    const VAULT_TEST_PLAINTEXT: &[u8] = b"health check";
    const VAULT_TEST_PASSWORD: &str = "throwaway-diagnostic-password-not-a-real-secret";

    let vault_summary = match SealedVault::seal(
        VAULT_TEST_PLAINTEXT,
        VAULT_TEST_PASSWORD,
        KdfParams::DESKTOP_DEFAULT,
    ) {
        Ok(vault) => match vault.open(VAULT_TEST_PASSWORD) {
            Ok(decrypted) if decrypted.as_bytes() == VAULT_TEST_PLAINTEXT => "vault: ok",
            _ => "vault: FAILED",
        },
        Err(_) => "vault: FAILED",
    };

    format!("{crypto_summary} | {vault_summary}")
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Two full builder chains rather than a shared `invoke_handler` binding:
    // `generate_handler!`'s output type isn't pinned down until it's chained
    // directly onto `.invoke_handler()`, so splitting it into a separate
    // `let` (even cfg-gated per branch) leaves the runtime type parameter
    // unresolved and fails to compile (E0282).
    #[cfg(debug_assertions)]
    {
        tauri::Builder::default()
            .plugin(tauri_plugin_opener::init())
            .invoke_handler(tauri::generate_handler![greet, core_health_check])
            .run(tauri::generate_context!())
            .expect("error while running tauri application");
    }
    #[cfg(not(debug_assertions))]
    {
        tauri::Builder::default()
            .plugin(tauri_plugin_opener::init())
            .invoke_handler(tauri::generate_handler![greet])
            .run(tauri::generate_context!())
            .expect("error while running tauri application");
    }
}
