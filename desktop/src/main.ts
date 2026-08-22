import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { decodeFunctionData, encodeFunctionData, erc20Abi, formatEther, formatGwei, formatUnits } from "viem";
import {
  DEFAULT_NETWORK,
  NETWORKS,
  allowedRpcOrigin,
  buildCustomNetworkConfig,
  rpcClient,
  validateCustomNetworkInput,
  type Address,
  type CustomNetworkFormInput,
  type NetworkConfig,
} from "./networks";
import { fetchTokenBalance, fetchTokenMetadata, parseUnitsStrict, type TokenMetadata } from "./tokens";
import {
  BASE_FEE_LAMPORTS_PER_SIGNATURE,
  SOL_DECIMALS,
  confirmSolanaTransaction,
  fetchLatestBlockhash,
  fetchSolanaBalanceLamports,
  formatLamportsAsSol,
  isValidSolanaAddress,
  sendRawSolanaTransaction,
} from "./solana";
import { fetchBitcoinBalanceSats, formatSatsAsBtc } from "./bitcoin";
import {
  EtherscanApiError,
  EtherscanConfigError,
  explorerTxUrl,
  fetchTokenTransfers,
  fetchTransactions,
  type EthTransaction,
  type TokenTransferEvent,
} from "./etherscan";

/**
 * Fixed intrinsic gas cost of a plain ETH transfer to an externally-owned
 * account (no contract call, no calldata) — a protocol constant (EIP-2's
 * G_transaction base cost), not an estimate. Every send destination the UI
 * currently offers is another derived account of this same wallet, i.e.
 * exactly that: a plain EOA. Nothing here calls `estimateGas`, because
 * there is nothing to estimate for this specific, fixed shape of
 * transaction.
 */
const ETH_TRANSFER_GAS_LIMIT = 21000n;

// Kept in step with MIN_PASSWORD_LEN in src-tauri/src/lib.rs, which is the
// authoritative check — this one only exists to fail fast in the UI.
// Counts characters rather than UTF-16 code units, to match the backend.
const MIN_PASSWORD_LENGTH = 12;

function characterCount(value: string): number {
  return [...value].length;
}

type Step =
  | "unlock"
  | "unlocked"
  | "setup"
  | "backup"
  | "confirm"
  | "done"
  | "send"
  | "send-confirm"
  | "send-status"
  | "reveal"
  | "solana-send"
  | "solana-send-confirm"
  | "solana-send-status";

const ALL_STEPS: Step[] = [
  "unlock",
  "unlocked",
  "setup",
  "backup",
  "confirm",
  "done",
  "send",
  "send-confirm",
  "send-status",
  "reveal",
  "solana-send",
  "solana-send-confirm",
  "solana-send-status",
];

/**
 * The generated phrase, held only as long as the backup and confirm screens
 * need it. It is never sent back to the backend — the confirm step transmits
 * only the slot numbers the user clicked, and the backend maps those to
 * phrase positions using the display order it generated and kept.
 */
let phraseWords: string[] = [];
/** Backend-supplied display order: slot `i` shows `phraseWords[bank[i]]`. */
let bank: number[] = [];
/** Slots the user has clicked, in click order. */
let selectedSlots: number[] = [];

/**
 * Which network is currently active — a built-in `NetworkId`, or a custom
 * network's generated id (see `customNetworks`, just below). Widened to
 * plain `string` rather than kept as `NetworkId` for exactly that reason:
 * this has to be able to hold either. Drives every RPC/Etherscan call and
 * the send flow's availability — see `switchNetwork` for what changes when
 * this does, and `networks.ts`/`customNetworks` for the per-network config
 * this indexes into. A UI preference, not secret-related state, so unlike
 * `accounts`/`activeAccountAddress` this is deliberately NOT reset by
 * `lock()` — the user's chosen network survives a lock/unlock cycle.
 */
let activeNetworkId: string = DEFAULT_NETWORK;

/**
 * Whether the "this is a different address" interstitial has already been
 * shown and dismissed once this session. Reset on lock — a fresh unlock
 * (even of the same wallet) is treated as a fresh session for this
 * purpose, since the whole point is catching a user who might not be
 * paying attention right now, not tracking whether they've *ever* seen it.
 */
let solanaInterstitialAcknowledged = false;

/** Same once-per-session gate as `solanaInterstitialAcknowledged`, for switching into the Bitcoin chain family — see `switchChainFamily`. */
let bitcoinInterstitialAcknowledged = false;

/**
 * Networks the user has added this session, keyed by their generated id
 * (`custom-1`, `custom-2`, ...). In-memory only, by design (see
 * `handleAddCustomNetwork`'s doc comment) — lost on restart, no persistence
 * attempted here; that's a separate future step once this app has a real
 * config storage format, not something to bolt on for this feature.
 */
const customNetworks = new Map<string, NetworkConfig>();
let nextCustomNetworkSeq = 1;

/** Look up `activeNetworkId` in either the built-in table or `customNetworks` — the one place both are treated as one namespace. */
function activeNetwork(): NetworkConfig {
  const network = getNetworkConfig(activeNetworkId);
  if (!network) {
    // Shouldn't happen: activeNetworkId is only ever set by switchNetwork,
    // to an id that was just confirmed to exist in one of these two
    // places. Falling back to the app's default rather than throwing keeps
    // a coding mistake here from crashing the whole UI.
    return NETWORKS[DEFAULT_NETWORK];
  }
  return network;
}

function getNetworkConfig(id: string): NetworkConfig | undefined {
  return (NETWORKS as Record<string, NetworkConfig>)[id] ?? customNetworks.get(id);
}

/**
 * The message shown instead of attempting a real request on a custom
 * network — see `NetworkConfig.isCustom`'s doc comment for why this is a
 * hard, immediate short-circuit rather than letting the request run and
 * fail: a custom RPC origin is never in `tauri.conf.json`'s static CSP
 * `connect-src`, so the webview would otherwise block it with no usable
 * error surfaced to a `catch` block at all (same underlying async-timing
 * reason `allowedRpcOrigin`'s own doc comment describes for the built-in
 * origin check). Checked at the very top of `fetchBalance`/`reviewSend`/
 * `confirmSend`, before any loading state is even shown, since the outcome
 * is already known.
 */
function customNetworkRpcBlockedMessage(network: NetworkConfig): string {
  return (
    `"${network.label}" is a custom network — its RPC endpoint isn't in this app's security ` +
    `policy allowlist, so requests to it are blocked. This is a known limitation for custom ` +
    `networks in this build, not a network problem.`
  );
}

/**
 * How many of the wallet's accounts the switcher derives and shows. Not a
 * protocol limit — the backend's `get_account_address` accepts any
 * non-hardened index — just a deliberate cap on what the UI exposes today,
 * so an open-ended "derive account #4 billion" input isn't something a user
 * can drive from here yet.
 */
const MAX_ACCOUNTS = 5;

interface WalletAccount {
  index: number;
  address: Address;
}

/**
 * Every account the switcher currently knows about, derived once per
 * unlock (see `loadAccounts`) via `MAX_ACCOUNTS` calls to
 * `get_account_address` — not re-derived on every read, since derivation
 * only depends on the mnemonic already in the backend's session and can't
 * change mid-session.
 */
let accounts: WalletAccount[] = [];

/**
 * A derived Solana account. Deliberately its own type, not a variant of
 * `WalletAccount`: a Solana address isn't `Address` (EVM's `0x`-prefixed,
 * EIP-55-checksummed hex type — see `networks.ts`), it's a plain Base58
 * string, and conflating the two would let a Solana address slip into an
 * EVM-typed slot (a send-destination field, an EVM RPC call) undetected by
 * the type system.
 */
interface SolanaWalletAccount {
  index: number;
  address: string;
}

/**
 * Every Solana account this wallet has actually created, derived once per
 * unlock (see `loadSolanaAccounts`) — real, persisted create/switch
 * accounting, mirroring how EVM's account switcher works, NOT a fixed
 * ceiling like EVM's `MAX_ACCOUNTS` still is (that's a known, separate,
 * not-yet-fixed gap on the EVM side). How many accounts exist is asked of
 * the backend (`get_solana_account_count`, backed by a persisted sidecar
 * file next to the vault — see that file's own doc comment in lib.rs) —
 * never assumed or hardcoded here.
 */
let solanaAccounts: SolanaWalletAccount[] = [];

/**
 * The wallet's single Bitcoin address, derived once per unlock (see
 * `loadBitcoinAccount`) at index 0 — unlike EVM/Solana's account
 * switchers, there is deliberately no multi-account support here yet, the
 * same "start with one account, add a switcher later" progression EVM and
 * Solana each began with. `null` until derivation resolves.
 */
let bitcoinAddress: string | null = null;

/** Which account in `accounts` is currently selected in the switcher. */
let activeAccountIndex = 0;

/**
 * `accounts[activeAccountIndex].address` — public data, freely usable for
 * a read-only balance query. Balance, token balances, and transaction
 * history all follow this, not a fixed account. Set on unlock and on every
 * switcher change, cleared on lock.
 */
let activeAccountAddress: Address | null = null;

/**
 * Bumped at the start of every balance fetch; a response only gets applied
 * if it's still the most recent request. Without this, clicking refresh
 * twice — or changing the RPC endpoint and refetching before the first
 * request has failed — could let a slow, stale response land *after* a
 * newer one and silently overwrite it, which is exactly the "stale balance
 * shown as if it were current" failure mode this feature must avoid.
 */
let balanceRequestId = 0;

/** Same stale-response guard as `balanceRequestId`, for the Solana SOL balance fetch. */
let solanaBalanceRequestId = 0;

/** Same stale-response guard as `balanceRequestId`, for the Bitcoin BTC balance fetch. */
let bitcoinBalanceRequestId = 0;

/**
 * Same stale-response guard as `balanceRequestId`, for the transaction
 * history fetch — a slow response from a previous fetch (or from before a
 * lock/unlock cycle) must never land after, and overwrite, a newer one.
 */
let txHistoryRequestId = 0;

/**
 * Same stale-response guard as `balanceRequestId`, for the token-balance
 * fetch. Bumped once per `fetchTokenBalances()` call (not once per token),
 * so a lock/unlock or RPC-change mid-fetch invalidates every in-flight
 * per-token read from that call together.
 */
let tokenBalanceRequestId = 0;

/**
 * Cache of each token's real, contract-read symbol/decimals, keyed by
 * `${chainId}:${address}` — NOT just address: a CREATE2-deployed contract
 * can legitimately sit at the identical address on two different chains
 * while being two unrelated tokens, so collapsing the key to address alone
 * would risk one network's cached metadata leaking into another's display.
 * Populated opportunistically whenever either the balance display
 * (`fetchTokenBalances`) or the send flow's token selector fetches a
 * token's metadata, and read by the transaction-history renderer so it can
 * label a token-transfer row without a fetch (and, on a cache miss, fall
 * back to a raw-units display rather than block rendering — see
 * `renderTxHistoryItem`). Never the SOURCE of truth for a signed amount:
 * every actual send re-fetches decimals fresh (see `handleAssetSelectionChanged`)
 * rather than trusting whatever happens to be cached.
 */
const tokenMetadataCache = new Map<string, TokenMetadata>();

function tokenCacheKey(chainId: number, address: Address): string {
  return `${chainId}:${address.toLowerCase()}`;
}

/**
 * The asset currently selected in the send flow's token picker. `null`
 * means ETH (a plain value transfer); otherwise the specific token being
 * sent, with its real, freshly-fetched decimals/symbol — never the cosmetic
 * `label` from the active network's token list (`NetworkConfig.tokens`).
 */
type SelectedAsset = { address: Address; symbol: string; decimals: number } | null;
let selectedAsset: SelectedAsset = null;

/**
 * Send-flow state, gathered on "Review send" and consumed on "Confirm and
 * send". All public data (a recipient address, an amount, network fee
 * fields) — nothing here is secret, unlike the phrase/passphrase state
 * above. Reset (`clearSendState`) on cancel, on returning to the wallet
 * after a send, and on lock.
 *
 * A discriminated union rather than one shape with optional token fields:
 * `confirmSend` has to pick between two entirely different backend
 * commands (`sign_transaction` vs `sign_token_transfer`), and a `kind` tag
 * makes that an exhaustive `switch` the compiler checks, instead of an
 * "if amountRaw is set" convention that's easy to get wrong on either side.
 */
interface PreparedEthSend {
  kind: "eth";
  recipient: Address;
  amountWei: bigint;
  nonce: number;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  gasLimit: bigint;
}
interface PreparedTokenSend {
  kind: "token";
  tokenAddress: Address;
  tokenSymbol: string;
  tokenDecimals: number;
  recipient: Address;
  amountRaw: bigint;
  nonce: number;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  gasLimit: bigint;
}
type PreparedSend = PreparedEthSend | PreparedTokenSend;
let preparedSend: PreparedSend | null = null;

/**
 * Everything `confirmSolanaSend` needs, populated by `reviewSolanaSend` and
 * consumed exactly once. Same shape/lifecycle as `PreparedSend` above, but
 * deliberately a separate type, not folded into that union: a Solana send
 * has no nonce, no gas, no per-token variant, and its own recipient type
 * (a validated Base58 string, not `Address`) — squeezing it into the EVM
 * shape would just mean fields that mean something different per `kind`.
 */
interface PreparedSolanaSend {
  recipient: string;
  lamports: bigint;
  recentBlockhash: string;
}
let preparedSolanaSend: PreparedSolanaSend | null = null;

/**
 * Which Solana account is active — set by `switchActiveSolanaAccount`,
 * read by `fetchSolanaBalance` and the send flow (`reviewSolanaSend`/
 * `confirmSolanaSend`). Mirrors EVM's `activeAccountIndex` exactly, now
 * that Solana has a real account switcher instead of always being 0.
 */
let activeSolanaAccountIndex = 0;

/**
 * The send-asset selector's option value for "the chain's own native
 * currency" (ETH, BNB, ...), as opposed to a specific token address.
 * Deliberately NOT the literal display symbol (that varies per network —
 * see `NetworkConfig.nativeCurrencySymbol`) — this sentinel is constant
 * across every network, so code that checks "is native currency selected"
 * doesn't need to know which network is active to do it.
 */
const NATIVE_ASSET_VALUE = "native";

function clearSendState() {
  preparedSend = null;
  selectedAsset = null;
  el<HTMLSelectElement>("send-asset-select").value = NATIVE_ASSET_VALUE;
  el("send-amount-unit").textContent = activeNetwork().nativeCurrencySymbol;
  el<HTMLInputElement>("send-amount").value = "";
  el<HTMLInputElement>("send-ack-checkbox").checked = false;
  el("send-status").textContent = "";
  el("send-error").textContent = "";
  el("send-confirm-error").textContent = "";
  el("send-progress").textContent = "";
  el("send-tx-hash").textContent = "";
  el("send-final-error").textContent = "";
  el("send-done-btn").classList.add("hidden");
}

function clearSolanaSendState() {
  preparedSolanaSend = null;
  el<HTMLInputElement>("solana-send-recipient").value = "";
  el<HTMLInputElement>("solana-send-amount").value = "";
  el<HTMLInputElement>("solana-send-ack-checkbox").checked = false;
  el("solana-send-status").textContent = "";
  el("solana-send-error").textContent = "";
  el("solana-send-confirm-error").textContent = "";
  el("solana-send-progress").textContent = "";
  el("solana-send-signature").textContent = "";
  el("solana-send-final-error").textContent = "";
  el("solana-send-done-btn").classList.add("hidden");
}

/**
 * Exact error string the backend returns from `get_account_address`
 * and `sign_transaction` when `UnlockedWallet` has no session — kept in
 * sync by hand with `"wallet is locked"` in `desktop/src-tauri/src/lib.rs`.
 *
 * Verified, not assumed: Tauri's `InvokeError` wraps `serde_json::to_value`
 * of the command's error value (`tauri-2.11.5/src/ipc/mod.rs`), so a
 * `Result<T, String>` command's `Err("wallet is locked")` is serialized as
 * the bare JSON string `"wallet is locked"` — the `catch` block for these
 * two commands receives exactly that string, not an `Error` object or any
 * other wrapper.
 */
const SESSION_LOCKED_ERROR = "wallet is locked";

/**
 * True if `error` is specifically the backend's "no session" error, as
 * opposed to some other failure (network trouble, a malformed input, an
 * actual signing failure) that happens to occur during a wallet-scoped
 * action. `String(error)` rather than a bare `===` so this stays correct
 * even if some future Tauri version wraps the value differently.
 */
function isSessionLockedError(error: unknown): boolean {
  return String(error) === SESSION_LOCKED_ERROR;
}

/**
 * Route back to the unlock screen with a message explaining *why* —
 * distinct from a generic error, and distinct from the deliberately-vague
 * wrong-passphrase message the unlock screen itself uses (this isn't a
 * password guess, so there is no oracle concern in naming the real cause
 * here). This is what turns the idle/blur session lock (see the Rust-side
 * `UnlockedWallet` doc comment) from a silent dead end — the original bug —
 * into a clearly attributable, immediately recoverable state.
 */
function handleSessionLocked() {
  clearSendState();
  clearSolanaSendState();
  showStep("unlock");
  el("unlock-error").textContent =
    "Your session locked due to inactivity — please unlock again.";
}

function el<T extends HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) {
    throw new Error(`missing element: ${id}`);
  }
  return node as T;
}

function showStep(step: Step) {
  for (const name of ALL_STEPS) {
    el(`step-${name}`).classList.toggle("hidden", name !== step);
  }
  // Navigating away from the reveal/export screen (to anywhere, including
  // itself) always scrubs whatever secret it was showing — see
  // `clearRevealSecrets`'s own doc comment for why this is unconditional
  // rather than only on an explicit "Hide"/"Back" click. This must run
  // for every step transition in the app, not just the ones the reveal
  // screen's own buttons trigger — lock(), lost focus, an error path
  // elsewhere, all funnel through this one function.
  if (step !== "reveal") {
    clearRevealSecrets();
  }
}

/**
 * Clear the passphrase inputs.
 *
 * Called on *every* exit from a flow that touched them, including error
 * paths — a passphrase left sitting in a DOM input is readable by any script
 * in the webview for as long as it stays there.
 */
function clearPassphraseInputs() {
  el<HTMLInputElement>("password").value = "";
  el<HTMLInputElement>("password-confirm").value = "";
  el<HTMLInputElement>("unlock-password").value = "";
}

/**
 * Drop our references to the phrase and wipe what it rendered into.
 *
 * JavaScript gives no way to actually scrub the underlying string memory —
 * the real guarantee lives on the Rust side, where the mnemonic is zeroized
 * on drop. This only bounds how long the UI holds a copy.
 */
function clearPhraseFromMemory() {
  phraseWords = [];
  bank = [];
  selectedSlots = [];
  el("phrase-list").replaceChildren();
  el("word-bank").replaceChildren();
  el("selected-words").replaceChildren();
}

/**
 * Scrub everything the reveal/export screen may currently be showing:
 * the revealed phrase, the revealed private key, and both passphrase
 * inputs on that screen. Called unconditionally on every navigation away
 * from "reveal" (see `showStep`) — not just from this screen's own
 * "Hide"/"Back" buttons — so there is no path (an error elsewhere, a
 * lock() from idle timeout, a window-blur handler) that leaves a phrase
 * or key rendered in the DOM after the user has left this screen.
 *
 * Same caveat as `clearPhraseFromMemory`: this bounds how long the UI
 * *displays* the secret, not a claim that the underlying JS string memory
 * is actually zeroized — that guarantee only exists on the Rust side.
 */
function clearRevealSecrets() {
  el("reveal-phrase-words").replaceChildren();
  el("reveal-phrase-words").classList.add("hidden");
  el("reveal-phrase-hide-btn").classList.add("hidden");
  el("reveal-phrase-auth").classList.add("hidden");
  el<HTMLInputElement>("reveal-phrase-password").value = "";
  el("reveal-phrase-error").textContent = "";

  el("export-key-value").textContent = "";
  el("export-key-value").classList.add("hidden");
  el("export-key-label").textContent = "";
  el("export-key-label").classList.add("hidden");
  el("export-key-hide-btn").classList.add("hidden");
  el("export-key-auth").classList.add("hidden");
  el<HTMLInputElement>("export-key-password").value = "";
  el("export-key-error").textContent = "";
}

/** Which chains an exported key from `chainFamily` is valid on — shown next to the revealed value so it can never be mistaken for chain-specific. */
function exportKeyValidityLabel(chainFamily: "evm" | "solana"): string {
  return chainFamily === "evm"
    ? "Valid on: Ethereum Mainnet, Polygon, Optimism, BNB Smart Chain, Arbitrum One, Base — the SAME key on all of these, not one key per chain."
    : "Valid on: Solana Mainnet only. This key does NOT work on any EVM chain.";
}

async function handleRevealPhraseConfirm() {
  const passwordEl = el<HTMLInputElement>("reveal-phrase-password");
  const errorEl = el("reveal-phrase-error");
  const confirmBtn = el<HTMLButtonElement>("reveal-phrase-confirm-btn");
  errorEl.textContent = "";

  confirmBtn.disabled = true;
  try {
    const phrase = await invoke<string>("reveal_mnemonic", { password: passwordEl.value });
    const words = phrase.split(/\s+/);

    const list = el("reveal-phrase-words");
    list.replaceChildren();
    for (const word of words) {
      const item = document.createElement("li");
      item.textContent = word;
      list.appendChild(item);
    }
    list.classList.remove("hidden");
    el("reveal-phrase-hide-btn").classList.remove("hidden");
    el("reveal-phrase-auth").classList.add("hidden");
  } catch (error) {
    errorEl.textContent = String(error);
  } finally {
    passwordEl.value = "";
    confirmBtn.disabled = false;
  }
}

async function handleExportKeyConfirm() {
  const passwordEl = el<HTMLInputElement>("export-key-password");
  const errorEl = el("export-key-error");
  const confirmBtn = el<HTMLButtonElement>("export-key-confirm-btn");
  const chainFamily = el<HTMLSelectElement>("export-chain-family").value as "evm" | "solana";
  const indexInput = el<HTMLInputElement>("export-account-index").value;
  errorEl.textContent = "";

  // 1-based in the UI (matching "Account 1"/"Account 2" everywhere else in
  // this app), converted to the 0-based index every derive() function
  // actually takes. Validated strictly -- a malformed or out-of-range
  // value is rejected here rather than sent to the backend to reject less
  // clearly.
  const accountNumber = Number(indexInput);
  if (!Number.isInteger(accountNumber) || accountNumber < 1) {
    errorEl.textContent = "Account number must be a whole number, 1 or greater.";
    return;
  }
  const index = accountNumber - 1;

  confirmBtn.disabled = true;
  try {
    const command = chainFamily === "evm" ? "export_evm_private_key" : "export_solana_private_key";
    const key = await invoke<string>(command, { password: passwordEl.value, index });

    el("export-key-label").textContent = exportKeyValidityLabel(chainFamily);
    el("export-key-label").classList.remove("hidden");
    el("export-key-value").textContent = key;
    el("export-key-value").classList.remove("hidden");
    el("export-key-hide-btn").classList.remove("hidden");
    el("export-key-auth").classList.add("hidden");
  } catch (error) {
    errorEl.textContent = String(error);
  } finally {
    passwordEl.value = "";
    confirmBtn.disabled = false;
  }
}

interface NewMnemonic {
  words: string[];
  bank: number[];
}

async function generatePhrase() {
  const errorEl = el("setup-error");
  errorEl.textContent = "";

  const wordCount = Number(
    (
      document.querySelector(
        'input[name="word-count"]:checked',
      ) as HTMLInputElement
    ).value,
  );

  try {
    const generated = await invoke<NewMnemonic>("generate_new_mnemonic", {
      wordCount,
    });
    phraseWords = generated.words;
    bank = generated.bank;
  } catch (error) {
    errorEl.textContent = String(error);
    clearPhraseFromMemory();
    return;
  }

  renderPhrase();
  showStep("backup");
}

function renderPhrase() {
  const list = el("phrase-list");
  list.replaceChildren();
  for (const word of phraseWords) {
    const item = document.createElement("li");
    item.textContent = word;
    list.appendChild(item);
  }
}

function startConfirmation() {
  selectedSlots = [];
  renderConfirmation();
  showStep("confirm");
}

function renderConfirmation() {
  const selectedList = el("selected-words");
  selectedList.replaceChildren();
  for (const slot of selectedSlots) {
    const item = document.createElement("li");
    item.textContent = phraseWords[bank[slot]];
    selectedList.appendChild(item);
  }

  const bankEl = el("word-bank");
  bankEl.replaceChildren();
  for (let slot = 0; slot < bank.length; slot++) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = phraseWords[bank[slot]];
    // Tracked by slot, not by text: a BIP-39 phrase can legitimately repeat
    // a word, and each occurrence has to be selectable exactly once.
    button.disabled = selectedSlots.includes(slot);
    button.addEventListener("click", () => {
      selectedSlots.push(slot);
      el("confirm-error").textContent = "";
      renderConfirmation();
    });
    bankEl.appendChild(button);
  }

  el("confirm-btn").toggleAttribute(
    "disabled",
    selectedSlots.length !== bank.length,
  );
}

async function confirmAndSeal() {
  const errorEl = el("confirm-error");
  const statusEl = el("confirm-status");
  const confirmBtn = el<HTMLButtonElement>("confirm-btn");
  errorEl.textContent = "";

  const password = el<HTMLInputElement>("password").value;
  const passwordConfirm = el<HTMLInputElement>("password-confirm").value;

  if (characterCount(password) < MIN_PASSWORD_LENGTH) {
    errorEl.textContent = `Passphrase must be at least ${MIN_PASSWORD_LENGTH} characters.`;
    clearPassphraseInputs();
    return;
  }
  if (password !== passwordConfirm) {
    errorEl.textContent = "Passphrases do not match.";
    clearPassphraseInputs();
    return;
  }

  // Argon2id at the desktop cost parameters takes several seconds by
  // design, and it blocks this call. Say so, and don't let the user
  // double-submit while it runs.
  statusEl.textContent = "Encrypting your wallet — this takes a few seconds…";
  confirmBtn.disabled = true;

  try {
    const address = await invoke<string>("confirm_and_seal_wallet", {
      // Only slot numbers cross the bridge. The backend holds the display
      // order and maps these back to phrase positions itself.
      selectedOrder: selectedSlots,
      password,
    });

    clearPhraseFromMemory();
    el("address").textContent = address;
    showStep("done");
  } catch (error) {
    errorEl.textContent = String(error);
    // Let the user retry the ordering; the backend keeps the phrase pending
    // on a mismatch precisely so a mis-click isn't fatal. The phrase itself
    // must stay for that retry — it is already on screen — but the
    // passphrase does not, so it goes.
    selectedSlots = [];
    renderConfirmation();
  } finally {
    // Runs on success and failure alike.
    clearPassphraseInputs();
    statusEl.textContent = "";
    confirmBtn.disabled = false;
  }
}

/**
 * Derive and render every account up to `MAX_ACCOUNTS`, called once right
 * after `unlock_wallet` succeeds. Populates `accounts`, resets the switcher
 * to account 0, and kicks off the first balance/history fetch for it.
 *
 * A failure partway through (a locked session — shouldn't happen this soon
 * after unlocking, but the idle sweeper is a background thread and could in
 * principle race it — or some other backend error) reports itself and
 * leaves `accounts` as whatever was derived so far, rather than presenting
 * a switcher with silently-missing entries.
 */
async function loadAccounts() {
  const errorEl = el("account-list-error");
  const select = el<HTMLSelectElement>("account-select");
  errorEl.textContent = "";
  accounts = [];
  select.replaceChildren();
  select.disabled = true;

  try {
    for (let index = 0; index < MAX_ACCOUNTS; index++) {
      const address = await invoke<string>("get_account_address", { index });
      accounts.push({ index, address: address as Address });
    }
  } catch (error) {
    if (isSessionLockedError(error)) {
      handleSessionLocked();
      return;
    }
    errorEl.textContent = `Could not derive accounts: ${String(error)}`;
  } finally {
    select.disabled = false;
  }

  if (accounts.length === 0) {
    return;
  }

  renderAccountSelect();
  switchActiveAccount(0);
  void loadSolanaAccounts();
  void loadBitcoinAccount();
}

/**
 * Derive and render the display-only Solana account list — see
 * `SolanaWalletAccount`'s doc comment for this phase's scope. Deliberately
 * a separate function/failure path from `loadAccounts`'s EVM derivation,
 * not folded into that loop: a Solana derivation failure must never abort
 * or blank out the EVM account switcher the rest of the app depends on, and
 * vice versa — the two are independent derivations over independent code
 * paths (see `crypto/src/solana.rs`'s module doc comment), so a bug in one
 * has no reason to take down the other.
 */
async function loadSolanaAccounts() {
  const errorEl = el("solana-account-error");
  const select = el<HTMLSelectElement>("solana-account-select");
  errorEl.textContent = "";
  solanaAccounts = [];
  select.replaceChildren();
  select.disabled = true;

  try {
    // How many accounts actually exist is asked of the backend every time
    // — never assumed — since it reflects real persisted state (see
    // `solanaAccounts`'s own doc comment) that can only grow via
    // `handleAddSolanaAccount`, not a constant this file gets to decide.
    const count = await invoke<number>("get_solana_account_count");
    for (let index = 0; index < count; index++) {
      const address = await invoke<string>("get_solana_account_address", { index });
      solanaAccounts.push({ index, address });
    }
  } catch (error) {
    if (isSessionLockedError(error)) {
      handleSessionLocked();
      return;
    }
    errorEl.textContent = `Could not derive Solana accounts: ${String(error)}`;
  } finally {
    select.disabled = false;
  }

  renderSolanaAccountSelect();
  if (solanaAccounts.length > 0) {
    switchActiveSolanaAccount(0);
  }
  updateSolanaInterstitialAddress();
}

/**
 * Populate the Solana account switcher from `solanaAccounts` — same option
 * text format (`Account N — address`) as EVM's `renderAccountSelect`, so
 * the two switchers read consistently even though they're for entirely
 * different address spaces (see the chain-family badge next to the active
 * address for that distinction).
 */
function renderSolanaAccountSelect() {
  const select = el<HTMLSelectElement>("solana-account-select");
  select.replaceChildren();
  for (const account of solanaAccounts) {
    const option = document.createElement("option");
    option.value = String(account.index);
    option.textContent = `Account ${account.index + 1} — ${account.address}`;
    select.appendChild(option);
  }
}

/**
 * Make `index` the active Solana account — mirrors `switchActiveAccount`
 * exactly: updates `activeSolanaAccountIndex`, reflects the choice in the
 * switcher (in case this was called programmatically, e.g. right after
 * `handleAddSolanaAccount`), updates the visible active-address line, and
 * refreshes the balance for the newly active account. `fetchSolanaBalance`
 * reads `activeSolanaAccountIndex` itself (see that function), so no
 * separate "which account" plumbing is needed here beyond setting it.
 */
function switchActiveSolanaAccount(index: number) {
  const account = solanaAccounts.find((a) => a.index === index);
  if (!account) {
    return;
  }
  activeSolanaAccountIndex = account.index;
  el("solana-active-address").textContent = account.address;
  el<HTMLSelectElement>("solana-account-select").value = String(account.index);
  void fetchSolanaBalance();
}

/**
 * Derive and persist one more Solana account (backend-side: see
 * `add_solana_account` in lib.rs), add it to `solanaAccounts`, re-render
 * the switcher, and make it the active account — the natural thing to want
 * right after adding one.
 */
async function handleAddSolanaAccount() {
  const errorEl = el("solana-add-account-error");
  const addBtn = el<HTMLButtonElement>("solana-add-account-btn");
  errorEl.textContent = "";
  addBtn.disabled = true;

  try {
    const address = await invoke<string>("add_solana_account");
    const index = solanaAccounts.length; // The backend derives the next unused index, same count this array already reflects.
    solanaAccounts.push({ index, address });
    renderSolanaAccountSelect();
    switchActiveSolanaAccount(index);
  } catch (error) {
    if (isSessionLockedError(error)) {
      handleSessionLocked();
      return;
    }
    errorEl.textContent = `Could not add an account: ${String(error)}`;
  } finally {
    addBtn.disabled = false;
  }
}

/**
 * Keep the "different address" interstitial's own address line current —
 * called both when Solana accounts finish (re)loading and when the
 * interstitial is about to be shown, so it's never stuck on a stale or
 * empty value regardless of which happens first.
 */
function updateSolanaInterstitialAddress() {
  const account = solanaAccounts.find((a) => a.index === 0);
  el("solana-interstitial-address").textContent = account ? account.address : "Loading…";
}

/**
 * Derive the wallet's single Bitcoin account (index 0), called once right
 * after unlock, mirroring `loadSolanaAccounts`'s own failure isolation: a
 * Bitcoin derivation failure must never abort or blank out the EVM/Solana
 * account state the rest of the app depends on, and vice versa.
 */
async function loadBitcoinAccount() {
  const errorEl = el("bitcoin-account-error");
  errorEl.textContent = "";
  bitcoinAddress = null;

  try {
    bitcoinAddress = await invoke<string>("get_bitcoin_account_address", { index: 0 });
  } catch (error) {
    if (isSessionLockedError(error)) {
      handleSessionLocked();
      return;
    }
    errorEl.textContent = `Could not derive the Bitcoin account: ${String(error)}`;
    return;
  }

  el("bitcoin-active-address").textContent = bitcoinAddress;
  updateBitcoinInterstitialAddress();
  void fetchBitcoinBalance();
}

/** Same purpose as `updateSolanaInterstitialAddress`, for the Bitcoin interstitial. */
function updateBitcoinInterstitialAddress() {
  el("bitcoin-interstitial-address").textContent = bitcoinAddress ?? "Loading…";
}

/**
 * Fetch and render the wallet's real BTC mainnet balance — see
 * `bitcoin.ts`'s module doc comment for the indexer endpoint's own
 * verification. Mirrors `fetchSolanaBalance`'s stale-response guard
 * (`bitcoinBalanceRequestId`) for the same reason: a slow response must
 * never land after a newer one (a double-click refresh, or a lock/unlock in
 * between) and get shown as current.
 */
async function fetchBitcoinBalance() {
  const valueEl = el("bitcoin-balance-value");
  const errorEl = el("bitcoin-balance-error");
  const refreshBtn = el<HTMLButtonElement>("refresh-bitcoin-balance-btn");

  const requestId = ++bitcoinBalanceRequestId;
  errorEl.textContent = "";

  if (!bitcoinAddress) {
    valueEl.textContent = "";
    return;
  }

  valueEl.textContent = "Loading balance…";
  valueEl.classList.add("loading");
  refreshBtn.disabled = true;

  try {
    const sats = await fetchBitcoinBalanceSats(bitcoinAddress);
    if (requestId !== bitcoinBalanceRequestId) {
      return; // Superseded by a newer request; drop this result.
    }
    valueEl.textContent = `${formatSatsAsBtc(sats)} BTC`;
    valueEl.classList.remove("loading");
  } catch (error) {
    if (requestId !== bitcoinBalanceRequestId) {
      return;
    }
    valueEl.textContent = "";
    valueEl.classList.remove("loading");
    errorEl.textContent = `Could not fetch BTC balance: ${error instanceof Error ? error.message : String(error)}`;
  } finally {
    if (requestId === bitcoinBalanceRequestId) {
      refreshBtn.disabled = false;
    }
  }
}

/**
 * Switch which curve family's panel is in view. This is the one place
 * that decides whether the "different address" interstitial is shown —
 * see `solanaInterstitialAcknowledged`'s own doc comment for why it's
 * once-per-session, not once-per-switch: re-showing it on every single
 * toggle back to Solana would train users to click through it without
 * reading, which defeats the point.
 *
 * Switching TO "evm" never shows an interstitial of its own. The risk
 * this whole mechanism exists for is specifically "a different, unrelated
 * address silently replaced the one you were just looking at" — EVM is
 * this app's default, always-first-seen address space, and every EVM
 * network already shares one address (see `network-banner`'s existing
 * mainnet/testnet distinction for that, a separate and already-solved
 * problem).
 */
function switchChainFamily(family: "evm" | "solana" | "bitcoin") {
  el("chain-family-evm-btn").classList.toggle("active", family === "evm");
  el("chain-family-evm-btn").setAttribute("aria-pressed", String(family === "evm"));
  el("chain-family-solana-btn").classList.toggle("active", family === "solana");
  el("chain-family-solana-btn").setAttribute("aria-pressed", String(family === "solana"));
  el("chain-family-bitcoin-btn").classList.toggle("active", family === "bitcoin");
  el("chain-family-bitcoin-btn").setAttribute("aria-pressed", String(family === "bitcoin"));

  el("evm-chain-panel").classList.toggle("hidden", family !== "evm");
  el("solana-chain-panel").classList.toggle("hidden", family !== "solana");
  el("bitcoin-chain-panel").classList.toggle("hidden", family !== "bitcoin");

  if (family === "solana") {
    updateSolanaInterstitialAddress();
    const showInterstitial = !solanaInterstitialAcknowledged;
    el("solana-interstitial").classList.toggle("hidden", !showInterstitial);
    el("solana-chain-content").classList.toggle("hidden", showInterstitial);
  }

  if (family === "bitcoin") {
    updateBitcoinInterstitialAddress();
    const showInterstitial = !bitcoinInterstitialAcknowledged;
    el("bitcoin-interstitial").classList.toggle("hidden", !showInterstitial);
    el("bitcoin-chain-content").classList.toggle("hidden", showInterstitial);
  }
}

/**
 * Fetch and render the ACTIVE Solana account's real SOL mainnet balance —
 * see `solana.ts`'s module doc comment for the RPC endpoint's own
 * verification. Mirrors `fetchBalance`'s stale-response guard
 * (`solanaBalanceRequestId`) for the same reason: a slow response from a
 * superseded request (double-click refresh, a switch to a different
 * account, or a lock/unlock in between) must never land after a newer one
 * and get shown as current.
 *
 * BUG FIX: this used to look up index 0 unconditionally, independent of
 * `activeSolanaAccountIndex` — harmless while only one Solana account
 * could ever exist, but wrong the moment a second one did: switching the
 * active account would move `activeSolanaAccountIndex` while the balance
 * shown stayed pinned to account 0 regardless. Now reads the same variable
 * `switchActiveSolanaAccount` sets, the same way `fetchBalance` already
 * follows `activeAccountAddress` on the EVM side.
 */
async function fetchSolanaBalance() {
  const valueEl = el("solana-balance-value");
  const errorEl = el("solana-balance-error");
  const refreshBtn = el<HTMLButtonElement>("refresh-solana-balance-btn");
  const account = solanaAccounts.find((a) => a.index === activeSolanaAccountIndex);

  const requestId = ++solanaBalanceRequestId;
  errorEl.textContent = "";

  if (!account) {
    valueEl.textContent = "";
    return;
  }

  valueEl.textContent = "Loading balance…";
  valueEl.classList.add("loading");
  refreshBtn.disabled = true;

  try {
    const lamports = await fetchSolanaBalanceLamports(account.address);
    if (requestId !== solanaBalanceRequestId) {
      return; // Superseded by a newer request; drop this result.
    }
    valueEl.textContent = `${formatLamportsAsSol(lamports)} SOL`;
    valueEl.classList.remove("loading");
  } catch (error) {
    if (requestId !== solanaBalanceRequestId) {
      return;
    }
    valueEl.textContent = "";
    valueEl.classList.remove("loading");
    errorEl.textContent = `Could not fetch SOL balance: ${error instanceof Error ? error.message : String(error)}`;
  } finally {
    if (requestId === solanaBalanceRequestId) {
      refreshBtn.disabled = false;
    }
  }
}

function renderAccountSelect() {
  const select = el<HTMLSelectElement>("account-select");
  select.replaceChildren();
  for (const account of accounts) {
    const option = document.createElement("option");
    option.value = String(account.index);
    option.textContent = `Account ${account.index + 1} — ${account.address}`;
    select.appendChild(option);
  }
}

/**
 * Make `index` the active account: updates `activeAccountIndex` and
 * `activeAccountAddress`, reflects the choice in the switcher (in case this
 * was called programmatically rather than from the switcher's own `change`
 * event), and refreshes balance/token-balance/transaction-history for the
 * newly active account — those three all key off `activeAccountAddress`
 * already, so no separate "which account" plumbing is needed there.
 */
function switchActiveAccount(index: number) {
  const account = accounts.find((a) => a.index === index);
  if (!account) {
    return;
  }
  activeAccountIndex = account.index;
  activeAccountAddress = account.address;
  el("unlocked-address").textContent = account.address;
  el<HTMLSelectElement>("account-select").value = String(account.index);
  void fetchBalance();
  void fetchTxHistory();
}

/**
 * Populate the network selector from `NETWORKS` plus `customNetworks` — one
 * line to add a *built-in* network here, same as everywhere else this
 * refactor touches; a custom network needs no code change at all, since
 * `customNetworks` is read directly.
 *
 * Grouped into "Mainnets" / "Custom" `<optgroup>`s rather than one flat
 * list, so a user-added network is never mistaken for one of this app's own
 * pre-verified built-ins. Testnets are deliberately excluded from this
 * selector entirely — see `NETWORKS`/`DEFAULT_NETWORK`'s own doc comments:
 * this app is mainnet-only in its user-facing surface, though the testnet
 * configs and `SENDABLE_CHAIN_IDS` allowlist remain in the codebase for
 * internal send-flow testing. Custom networks are always shown; this app
 * doesn't classify a user-entered chain as testnet or mainnet at all (see
 * `NetworkConfig.isCustom`'s own doc comment).
 *
 * Never filters out the currently active network, even if some future code
 * path ends up with a testnet active — see the "blank page" incident this
 * function's git history records: an earlier version force-switched away
 * from a hidden-but-active network via `switchNetwork(DEFAULT_NETWORK)`,
 * and when `DEFAULT_NETWORK` itself was a hidden testnet, that recursed
 * infinitely before the app ever rendered past its static heading. Keeping
 * the active network unconditionally visible avoids reintroducing that
 * class of bug even though `DEFAULT_NETWORK` is a mainnet today.
 */
function renderNetworkSelect() {
  const select = el<HTMLSelectElement>("network-select");
  select.replaceChildren();

  const mainnetGroup = document.createElement("optgroup");
  mainnetGroup.label = "Mainnets";
  const customGroup = document.createElement("optgroup");
  customGroup.label = "Custom";

  for (const network of Object.values(NETWORKS)) {
    if (network.isTestnet && network.id !== activeNetworkId) {
      continue;
    }
    const option = document.createElement("option");
    option.value = network.id;
    option.textContent = network.isTestnet ? `${network.label} · TEST` : network.label;
    mainnetGroup.appendChild(option);
  }
  for (const network of customNetworks.values()) {
    const option = document.createElement("option");
    option.value = network.id;
    option.textContent = network.label;
    customGroup.appendChild(option);
  }

  select.appendChild(mainnetGroup);
  if (customGroup.childElementCount > 0) {
    select.appendChild(customGroup);
  }
  select.value = activeNetworkId;
}

/**
 * Make `networkId` the active network: points the RPC-url field at that
 * network's own verified default (never carries over the previous
 * network's override — leaving one network's RPC URL sitting in the field
 * while the banner says another is exactly the confused-about-which-
 * network-I'm-looking-at state this feature has to avoid), refreshes the
 * network selector/banner/send-availability, and re-fetches
 * balance/token-balances/history for the newly active network. Account
 * addresses themselves don't change across networks (same derivation,
 * same address format on every EVM chain) — only what's fetched about them
 * does, so `accounts`/`activeAccountIndex` are untouched here.
 */
function switchNetwork(networkId: string) {
  if (!getNetworkConfig(networkId)) {
    return;
  }
  activeNetworkId = networkId;
  const network = activeNetwork();
  el<HTMLInputElement>("rpc-url").value = network.defaultRpcUrl;
  renderNetworkSelect();
  renderNetworkBanner();
  updateSendAvailability();
  if (activeAccountAddress) {
    void fetchBalance();
    void fetchTxHistory();
  }
}

/**
 * Make it visually unmistakable which network is active — required
 * reading before trusting any balance shown below it, since every mainnet
 * here shows real value and every testnet doesn't. Distinct color/wording
 * per network *kind* (`isTestnet`, not `sendSupported` — even though the
 * two happen to correlate for every built-in network today, see
 * `NetworkConfig.isTestnet`'s own doc comment on why they're deliberately
 * separate flags) rather than just swapping a label: a color change is
 * legible at a glance, in a way plain text sitting next to a dropdown is
 * not.
 *
 * Also renders the separate, persistent "not vetted" warning for a custom
 * network — required reading distinct from the mainnet/testnet banner
 * itself, since it's a different kind of caution (unverified RPC source,
 * not "real funds").
 */
function renderNetworkBanner() {
  const network = activeNetwork();
  const bannerEl = el("network-banner");
  bannerEl.textContent = network.isTestnet
    ? network.label
    : `${network.label} — real funds${network.sendSupported ? "" : ", read-only (sending not supported yet)"}`;
  bannerEl.classList.toggle("network-banner-mainnet", !network.isTestnet);
  bannerEl.classList.toggle("network-banner-testnet", network.isTestnet);

  const warningEl = el("custom-network-warning");
  warningEl.classList.toggle("hidden", !network.isCustom);
  if (network.isCustom) {
    warningEl.textContent =
      `"${network.label}" is a custom network. Its RPC endpoint has not been vetted by this app — ` +
      `unlike the built-in networks, it could theoretically serve incorrect balances or history. ` +
      `Balance and send requests to it are also blocked by this app's security policy for now (see below).`;
  }
}

/**
 * Reflect the active network's `sendSupported` flag in the Send button
 * itself — disabled with an explanatory hint, so a user on an unsupported
 * network sees the restriction before entering the send flow at all, not
 * after filling out a form and clicking through to review. `goToSend`
 * still checks this too (defense in depth against a stale disabled state),
 * but the button being disabled is what actually satisfies "show this
 * clearly up front."
 */
function updateSendAvailability() {
  const network = activeNetwork();
  el<HTMLButtonElement>("send-nav-btn").disabled = !network.sendSupported;
  el("send-nav-hint").textContent = network.sendSupported
    ? ""
    : `Sending is not supported on ${network.label} yet.`;
}

function readCustomNetworkFormInput(): CustomNetworkFormInput {
  return {
    label: el<HTMLInputElement>("custom-network-name").value,
    rpcUrl: el<HTMLInputElement>("custom-network-rpc-url").value,
    chainIdInput: el<HTMLInputElement>("custom-network-chain-id").value,
    nativeCurrencySymbol: el<HTMLInputElement>("custom-network-currency").value,
    explorerBaseUrlInput: el<HTMLInputElement>("custom-network-explorer-url").value,
  };
}

function clearCustomNetworkForm() {
  el<HTMLInputElement>("custom-network-name").value = "";
  el<HTMLInputElement>("custom-network-rpc-url").value = "";
  el<HTMLInputElement>("custom-network-chain-id").value = "";
  el<HTMLInputElement>("custom-network-currency").value = "";
  el<HTMLInputElement>("custom-network-explorer-url").value = "";
  el("custom-network-error").textContent = "";
}

function showCustomNetworkForm() {
  clearCustomNetworkForm();
  el("custom-network-form").classList.remove("hidden");
}

function hideCustomNetworkForm() {
  el("custom-network-form").classList.add("hidden");
  clearCustomNetworkForm();
}

/**
 * Validate the custom-network form and, on success, add it to
 * `customNetworks` and switch to it immediately — so the newly-added
 * network's persistent "not vetted" warning (see `renderNetworkBanner`) is
 * the very next thing the user sees, not something they'd have to go find
 * in the selector afterward.
 *
 * In-memory only, by design: `customNetworks` is a plain `Map`, not
 * written anywhere on disk. Losing custom networks on restart is the
 * accepted, deliberate scope of this feature for now — real persistence
 * needs its own config storage format decision, not something to bolt on
 * here just because it would be easy to `JSON.stringify` a `Map`.
 */
function handleAddCustomNetwork() {
  const errorEl = el("custom-network-error");
  errorEl.textContent = "";

  const existingNetworks = [...Object.values(NETWORKS), ...customNetworks.values()];
  const result = validateCustomNetworkInput(readCustomNetworkFormInput(), existingNetworks);
  if (!result.ok) {
    errorEl.textContent = result.error;
    return;
  }

  const id = `custom-${nextCustomNetworkSeq++}`;
  customNetworks.set(id, buildCustomNetworkConfig(id, result.value));

  hideCustomNetworkForm();
  switchNetwork(id);
}

/**
 * Fetch and render the active network's native-currency balance (ETH, BNB,
 * ... — see `NetworkConfig.nativeCurrencySymbol`) for `activeAccountAddress`,
 * using whatever RPC URL is currently in the override field.
 *
 * No secret material anywhere in this path: an address and a balance are
 * both public. This function never touches `invoke`, the vault, or any
 * passphrase/mnemonic state — it's plain read-only chain data over HTTP.
 */
async function fetchBalance() {
  const valueEl = el("balance-value");
  const errorEl = el("balance-error");
  const refreshBtn = el<HTMLButtonElement>("refresh-balance-btn");
  const rpcUrl = el<HTMLInputElement>("rpc-url").value.trim();
  const network = activeNetwork();

  if (!activeAccountAddress) {
    return;
  }

  const requestId = ++balanceRequestId;
  errorEl.textContent = "";

  if (network.isCustom) {
    errorEl.textContent = customNetworkRpcBlockedMessage(network);
    return;
  }

  if (!rpcUrl) {
    errorEl.textContent = "Enter an RPC endpoint URL.";
    return;
  }

  // Checked before touching the network at all — not by reacting to a CSP
  // violation after the fact. See `allowedRpcOrigin`'s doc comment: a
  // securitypolicyviolation event does fire for a blocked connect-src
  // request, but confirmed (empirically, not assumed) to always arrive
  // after a fetch's rejection is already handled, so it cannot be used to
  // produce this message from inside a catch block.
  let origin: string;
  try {
    origin = new URL(rpcUrl).origin;
  } catch {
    errorEl.textContent = `"${rpcUrl}" is not a valid URL.`;
    return;
  }
  if (origin !== allowedRpcOrigin(network)) {
    errorEl.textContent =
      `This app's security policy only allows ${network.label}'s default endpoint ` +
      `(${network.defaultRpcUrl}) right now. "${rpcUrl}" would be blocked.`;
    return;
  }

  // Loading state: explicit, not just leaving the previous value on screen.
  // A balance that's actually stale (mid-refresh, or left over from before
  // an error) must never be visually indistinguishable from a fresh one.
  valueEl.textContent = "Loading balance…";
  valueEl.classList.add("loading");
  refreshBtn.disabled = true;

  // Independent of the ETH balance fetch below (its own request-id guard,
  // its own per-token error handling) — a slow or failing token read must
  // never block or blank out the ETH balance, and vice versa.
  void fetchTokenBalances(network, rpcUrl);

  try {
    const balanceWei = await rpcClient(network, rpcUrl).getBalance({
      address: activeAccountAddress,
    });

    if (requestId !== balanceRequestId) {
      return; // Superseded by a newer request; drop this result.
    }
    valueEl.textContent = `${formatEther(balanceWei)} ${network.nativeCurrencySymbol}`;
    valueEl.classList.remove("loading");
  } catch (error) {
    if (requestId !== balanceRequestId) {
      return;
    }
    // Failure clears the display rather than leaving the old value up —
    // showing a last-known balance during/after an error would misrepresent
    // it as current.
    valueEl.textContent = "";
    valueEl.classList.remove("loading");

    // A CSP block can no longer reach here — it's caught by the
    // allowedRpcOrigin check above before this try block starts. This is
    // a genuine network/RPC failure: unreachable host, timeout, bad
    // response, etc.
    errorEl.textContent = `Could not fetch balance: ${error instanceof Error ? error.message : String(error)}`;
  } finally {
    if (requestId === balanceRequestId) {
      refreshBtn.disabled = false;
    }
  }
}

/**
 * Fetch and render each of `network`'s tokens' balance for
 * `activeAccountAddress`, over `rpcUrl` (already validated by the caller —
 * `fetchBalance` — against `allowedRpcOrigin(network)`, so this trusts it
 * as-is rather than re-checking).
 *
 * Each token is fetched independently: a failing contract read (bad RPC
 * response, a token temporarily returning garbage, whatever) shows an error
 * on *that token's* row only, via `renderTokenRow`'s error branch — it
 * never takes down the rest of the list. This is why the per-token
 * `Promise` calls below are not wrapped in a single `Promise.all`.
 */
async function fetchTokenBalances(network: NetworkConfig, rpcUrl: string) {
  const listEl = el("token-balance-list");

  if (!activeAccountAddress) {
    return;
  }
  const owner = activeAccountAddress;

  const requestId = ++tokenBalanceRequestId;
  listEl.replaceChildren();

  const client = rpcClient(network, rpcUrl);

  for (const { address: tokenAddress } of network.tokens) {
    const row = renderTokenRow({ address: tokenAddress, state: "loading" });
    listEl.appendChild(row);

    fetchTokenBalance(client, tokenAddress, owner)
      .then((result) => {
        // Opportunistically warms the cache the transaction-history
        // renderer reads to label a token-transfer row -- this fetch was
        // happening anyway, so there's no extra request for that benefit.
        tokenMetadataCache.set(tokenCacheKey(network.chainId, tokenAddress), {
          symbol: result.symbol,
          decimals: result.decimals,
        });
        if (requestId !== tokenBalanceRequestId) {
          return; // Superseded by a newer fetch (refresh, lock, RPC change).
        }
        row.replaceWith(renderTokenRow({ ...result, state: "loaded" }));
      })
      .catch((error) => {
        if (requestId !== tokenBalanceRequestId) {
          return;
        }
        row.replaceWith(
          renderTokenRow({
            address: tokenAddress,
            state: "error",
            message: error instanceof Error ? error.message : String(error),
          }),
        );
      });
  }
}

type TokenRowState =
  | { address: Address; state: "loading" }
  | { address: Address; state: "error"; message: string }
  | { address: Address; state: "loaded"; symbol: string; decimals: number; balance: bigint };

function renderTokenRow(row: TokenRowState): HTMLLIElement {
  const item = document.createElement("li");
  item.className = "token-balance-item";

  if (row.state === "loading") {
    item.textContent = "Loading…";
    item.classList.add("hint");
    return item;
  }

  if (row.state === "error") {
    item.classList.add("error");
    item.textContent = `${row.address}: could not read balance (${row.message})`;
    return item;
  }

  const symbolEl = document.createElement("span");
  symbolEl.className = "token-symbol";
  symbolEl.textContent = row.symbol;
  item.appendChild(symbolEl);

  const amountEl = document.createElement("span");
  amountEl.className = "token-amount";
  // formatUnits, not formatEther — formatEther is fixed to 18 decimals,
  // which is wrong for a token whose *actual, contract-reported* decimals
  // (never assumed — see tokens.ts) differ, as most non-ETH tokens do.
  amountEl.textContent = ` ${formatUnits(row.balance, row.decimals)}`;
  item.appendChild(amountEl);

  return item;
}

/** Turn a caught fetch error into the message this app shows for it, uniformly wherever history reports a failure. */
function describeEtherscanError(error: unknown): string {
  if (error instanceof EtherscanConfigError) {
    return `unavailable: ${error.message}`;
  }
  if (error instanceof EtherscanApiError) {
    return error.message;
  }
  return String(error);
}

/**
 * Fetch and render `activeAccountAddress`'s transaction history on the
 * active network, merging two Etherscan endpoints (see the top-level doc
 * comment in `etherscan.ts` for why both are needed): `txlist` for plain
 * ETH activity, `tokentx` for ERC-20 transfers sent OR received. The two
 * are fetched concurrently and independently — one failing must not hide
 * the other's data.
 *
 * Three end states, kept visually distinct rather than collapsed into one
 * blank-or-generic screen: a genuine empty history (new wallet, nothing
 * sent or received yet), an error (both sources unreachable, rate-limited,
 * or unconfigured), and the populated list. A fourth, partial-failure case
 * — one source loaded, the other didn't — still shows whatever data loaded,
 * with a non-blocking note rather than hiding it behind a full error state.
 */
async function fetchTxHistory() {
  const statusEl = el("tx-history-status");
  const errorEl = el("tx-history-error");
  const emptyEl = el("tx-history-empty");
  const listEl = el("tx-history-list");
  const refreshBtn = el<HTMLButtonElement>("refresh-tx-history-btn");

  if (!activeAccountAddress) {
    return;
  }
  const address = activeAccountAddress;
  const network = activeNetwork();

  const requestId = ++txHistoryRequestId;
  errorEl.textContent = "";
  emptyEl.classList.add("hidden");
  listEl.replaceChildren();
  statusEl.textContent = "Loading transaction history…";
  refreshBtn.disabled = true;

  // Best-effort warm-up so a token-transfer row (from either source) can
  // usually render its real symbol/decimals without an extra fetch of its
  // own. Never blocks or fails history loading: a rejected token-info read
  // here just means those rows fall back to a raw-units or Etherscan-
  // reported display instead of this app's own contract-read one.
  const rpcUrl = el<HTMLInputElement>("rpc-url").value.trim();
  if (rpcUrl) {
    const client = rpcClient(network, rpcUrl);
    void Promise.all(
      network.tokens
        .filter((t) => !tokenMetadataCache.has(tokenCacheKey(network.chainId, t.address)))
        .map(async (t) => {
          try {
            tokenMetadataCache.set(
              tokenCacheKey(network.chainId, t.address),
              await fetchTokenMetadata(client, t.address),
            );
          } catch {
            // See comment above: best-effort only.
          }
        }),
    );
  }

  try {
    const [txResult, tokenResult] = await Promise.allSettled([
      fetchTransactions(network.chainId, address),
      fetchTokenTransfers(network.chainId, address),
    ]);

    if (requestId !== txHistoryRequestId) {
      return; // Superseded by a newer request; drop this result.
    }
    statusEl.textContent = "";

    if (txResult.status === "rejected" && tokenResult.status === "rejected") {
      errorEl.textContent = `Could not load transaction history: ${describeEtherscanError(txResult.reason)}`;
      return;
    }

    const transactions = txResult.status === "fulfilled" ? txResult.value : [];
    const tokenTransfers = tokenResult.status === "fulfilled" ? tokenResult.value : [];
    const merged = mergeHistory(network, transactions, tokenTransfers);

    if (merged.length === 0) {
      emptyEl.classList.remove("hidden");
    } else {
      renderTxHistory(merged);
    }

    // One source failed, the other didn't: the data that DID load is still
    // shown above (or the empty state, if the successful source really was
    // empty) — this is a note about possible incompleteness, not a reason
    // to hide what loaded.
    if (txResult.status === "rejected") {
      errorEl.textContent = `Some history may be missing: ${describeEtherscanError(txResult.reason)}`;
    } else if (tokenResult.status === "rejected") {
      errorEl.textContent = `Token transfers may be missing: ${describeEtherscanError(tokenResult.reason)}`;
    }
  } finally {
    if (requestId === txHistoryRequestId) {
      refreshBtn.disabled = false;
    }
  }
}

/** One row's worth of already-decided display data, independent of which Etherscan endpoint it came from. */
interface HistoryItem {
  hash: string;
  timestamp: number;
  render: () => HTMLLIElement;
}

/**
 * Merge `txlist` and `tokentx` results into one newest-first list, with
 * `tokentx` treated as authoritative for any hash it covers (per the task
 * this feature implements: it has the real token details `txlist` alone
 * can't provide) — so a `txlist` entry is dropped whenever its hash also
 * appears in `tokentx`, to avoid showing the same transaction twice.
 *
 * This does NOT lose the failed-token-transfer edge case: a reverted
 * `transfer()` call emits no `Transfer` event, so it never appears in
 * `tokentx` at all, meaning its hash was never in `tokenHashes` to begin
 * with — that entry passes through from `transactions` untouched and is
 * still rendered by `renderTxHistoryItem`'s own `describeTokenTransfer`
 * detection (see that function), just correctly marked "Failed" rather
 * than misrepresented as a mystery 0-ETH send.
 */
function mergeHistory(
  network: NetworkConfig,
  transactions: EthTransaction[],
  tokenTransfers: TokenTransferEvent[],
): HistoryItem[] {
  const tokenHashes = new Set(tokenTransfers.map((t) => t.hash.toLowerCase()));

  const items: HistoryItem[] = tokenTransfers.map((event) => ({
    hash: event.hash,
    timestamp: event.timestamp,
    render: () => renderTokenTransferItem(network, event),
  }));

  for (const tx of transactions) {
    if (tokenHashes.has(tx.hash.toLowerCase())) {
      continue; // tokentx already represents this hash, with the real token details.
    }
    items.push({
      hash: tx.hash,
      timestamp: tx.timestamp,
      render: () => renderTxHistoryItem(network, tx),
    });
  }

  items.sort((a, b) => b.timestamp - a.timestamp);
  return items;
}

function renderTxHistory(items: HistoryItem[]) {
  const listEl = el("tx-history-list");
  listEl.replaceChildren();

  for (const item of items) {
    listEl.appendChild(item.render());
  }
}

interface TokenTransferDescription {
  tokenAddress: Address;
  recipient: Address;
  amountRaw: bigint;
}

/**
 * If `tx` calls `transfer(address,uint256)` on a token `network` knows
 * about (`network.tokens`), decode the real recipient and amount;
 * otherwise `null` (a plain value transfer, or a call to some other
 * contract/function this app doesn't render specially).
 *
 * By the time this runs, `mergeHistory` has already dropped every `txlist`
 * entry whose hash is also in `tokentx` — so a token-shaped transaction
 * reaching this function is specifically the case `tokentx` can't cover: a
 * *failed* transfer() call, which reverted before emitting a `Transfer`
 * event and so was never indexed there. A successful send is rendered via
 * `renderTokenTransferItem` instead, from the richer `tokentx` data.
 */
function describeTokenTransfer(
  network: NetworkConfig,
  tx: EthTransaction,
): TokenTransferDescription | null {
  if (tx.to === null) {
    return null;
  }
  const token = network.tokens.find((t) => t.address.toLowerCase() === tx.to?.toLowerCase());
  if (!token) {
    return null;
  }
  try {
    const decoded = decodeFunctionData({ abi: erc20Abi, data: tx.input });
    if (decoded.functionName !== "transfer") {
      return null;
    }
    const [recipient, amountRaw] = decoded.args;
    return { tokenAddress: token.address, recipient, amountRaw };
  } catch {
    return null; // Not a well-formed transfer() call -- not this function's job to render.
  }
}

/**
 * Shared DOM structure for one history row, independent of which Etherscan
 * endpoint (or which branch of `renderTxHistoryItem`) produced its fields —
 * one place building the summary/other-party/timestamp/explorer-link
 * layout, so `renderTxHistoryItem` and `renderTokenTransferItem` can't
 * silently drift into two different-looking row shapes.
 */
function renderHistoryRow(row: {
  direction: string;
  amountDisplay: string;
  status: { label: string; failed: boolean };
  otherPartyDisplay: string;
  timestamp: number;
  hash: string;
  explorerBaseUrl: string;
}): HTMLLIElement {
  const item = document.createElement("li");
  item.className = "tx-history-item";

  const summary = document.createElement("div");
  summary.className = "tx-history-summary";

  const directionEl = document.createElement("span");
  directionEl.className = `tx-direction tx-direction-${row.direction.toLowerCase()}`;
  directionEl.textContent = row.direction;
  summary.appendChild(directionEl);

  const amountEl = document.createElement("span");
  amountEl.className = "tx-amount";
  amountEl.textContent = row.amountDisplay;
  summary.appendChild(amountEl);

  const statusEl = document.createElement("span");
  statusEl.className = `tx-status ${row.status.failed ? "tx-status-failed" : "tx-status-success"}`;
  statusEl.textContent = row.status.label;
  summary.appendChild(statusEl);

  item.appendChild(summary);

  const otherPartyEl = document.createElement("p");
  otherPartyEl.className = "address tx-other-party";
  otherPartyEl.textContent = row.otherPartyDisplay;
  item.appendChild(otherPartyEl);

  const timeEl = document.createElement("p");
  timeEl.className = "hint tx-timestamp";
  timeEl.textContent = new Date(row.timestamp * 1000).toLocaleString();
  item.appendChild(timeEl);

  // A custom network with no explorer URL entered has nothing to link to
  // (see NetworkConfig.explorerBaseUrl's doc comment) -- no button at all,
  // rather than one that opens a broken URL.
  if (row.explorerBaseUrl) {
    const viewBtn = document.createElement("button");
    viewBtn.type = "button";
    viewBtn.textContent = "View on explorer";
    viewBtn.addEventListener("click", () => {
      // Opened in the system's default browser (Tauri's opener plugin), not
      // an in-app view — the whole point is letting the user independently
      // verify what this app shows them, on a page this app doesn't control.
      void openUrl(explorerTxUrl(row.explorerBaseUrl, row.hash));
    });
    item.appendChild(viewBtn);
  }

  return item;
}

function renderTxHistoryItem(network: NetworkConfig, tx: EthTransaction): HTMLLIElement {
  const address = activeAccountAddress as Address;
  const tokenTransfer = describeTokenTransfer(network, tx);

  // A token-transfer row reaching this function is always the
  // failed-transfer edge case (see describeTokenTransfer's doc comment) —
  // and a failed call, from this wallet's own account, is always a "Sent"
  // in intent even though it never actually moved anything.
  let direction: string;
  let otherParty: string;
  let amountDisplay: string;

  if (tokenTransfer) {
    direction = "Sent";
    otherParty = tokenTransfer.recipient;
    const metadata = tokenMetadataCache.get(tokenCacheKey(network.chainId, tokenTransfer.tokenAddress));
    amountDisplay = metadata
      ? `${formatUnits(tokenTransfer.amountRaw, metadata.decimals)} ${metadata.symbol}`
      // Cache miss (rare -- see fetchTxHistory's warm-up): still correctly
      // NOT "0 ETH", the bug this whole function exists to avoid, just
      // without a human-readable amount until the token's decimals are
      // known. Never guesses a decimals value to force a display here.
      : `${tokenTransfer.amountRaw} raw units of token ${tokenTransfer.tokenAddress} (decimals unknown)`;
  } else {
    const isFromUs = tx.from.toLowerCase() === address.toLowerCase();
    const isToUs = tx.to !== null && tx.to.toLowerCase() === address.toLowerCase();

    // Self-sends (account 2 test transfers, e.g.) are both at once —
    // labeled as their own case rather than picked arbitrarily as one or
    // the other, since "sent" or "received" alone would each be half true.
    if (isFromUs && isToUs) {
      direction = "Self";
      otherParty = address;
    } else if (isFromUs) {
      direction = "Sent";
      otherParty = tx.to ?? "(contract creation)";
    } else {
      direction = "Received";
      otherParty = tx.from;
    }
    amountDisplay = `${formatEther(tx.valueWei)} ${network.nativeCurrencySymbol}`;
  }

  return renderHistoryRow({
    direction,
    amountDisplay,
    status: { label: tx.failed ? "Failed" : "Success", failed: tx.failed },
    otherPartyDisplay: direction === "Self" ? "This wallet's own address" : otherParty,
    timestamp: tx.timestamp,
    hash: tx.hash,
    explorerBaseUrl: network.explorerBaseUrl,
  });
}

/**
 * Render one `tokentx`-sourced row — a successful ERC-20 transfer, sent OR
 * received (unlike `renderTxHistoryItem`'s token-transfer branch, which can
 * only ever be a failed send — see that function's doc comment). A
 * `tokentx` entry has no separate failed/success state to report: a
 * reverted call emits no `Transfer` event, so every event this endpoint
 * returns already represents a transfer that genuinely happened.
 */
function renderTokenTransferItem(network: NetworkConfig, event: TokenTransferEvent): HTMLLIElement {
  const address = activeAccountAddress as Address;
  const isFromUs = event.from.toLowerCase() === address.toLowerCase();
  const isToUs = event.to.toLowerCase() === address.toLowerCase();

  let direction: string;
  let otherParty: string;
  if (isFromUs && isToUs) {
    direction = "Self";
    otherParty = address;
  } else if (isFromUs) {
    direction = "Sent";
    otherParty = event.to;
  } else {
    direction = "Received";
    otherParty = event.from;
  }

  // Prefers this app's own contract-read metadata (from balance fetches or
  // the send flow's token selector) over Etherscan's self-reported
  // tokenSymbol/tokenDecimal fields when available -- consistent with this
  // codebase's rule of never trusting a single source for decimals where
  // avoidable. Falls back to Etherscan's values rather than blocking
  // render on a fetch of its own; see etherscan.ts's top-level doc comment
  // on why that fallback is still reasonably trustworthy.
  const metadata = tokenMetadataCache.get(tokenCacheKey(network.chainId, event.tokenAddress));
  const decimals = metadata?.decimals ?? event.tokenDecimals;
  const symbol = metadata?.symbol ?? event.tokenSymbol;

  return renderHistoryRow({
    direction,
    amountDisplay: `${formatUnits(event.amountRaw, decimals)} ${symbol}`,
    status: { label: "Success", failed: false },
    otherPartyDisplay: direction === "Self" ? "This wallet's own address" : otherParty,
    timestamp: event.timestamp,
    hash: event.hash,
    explorerBaseUrl: network.explorerBaseUrl,
  });
}

/**
 * Enter the send flow: check the session is still unlocked, then populate
 * the destination picker with every derived account other than the
 * currently-active one, and show the amount-entry screen.
 *
 * Restricted to the wallet's own other accounts, not arbitrary addresses —
 * free-form recipients are a later step with their own address-entry
 * validation UX. The active account is excluded from its own destination
 * list: sending an account to itself is a no-op the picker shouldn't offer.
 *
 * The lock check is deliberately real IPC (`get_account_address` for the
 * active account, whose result is otherwise unused here — `accounts` was
 * already derived by `loadAccounts` and doesn't change mid-session, so this
 * call exists purely to force a round-trip to the backend), not something
 * inferred from cached frontend state. This is a *second*, early copy of
 * the same check `sign_transaction` already enforces in `confirmSend` — not
 * a replacement for it: catching a locked session here means a user who's
 * been idle finds out the moment they click "Send," rather than after
 * filling out and reviewing an entire transaction only to be bounced at
 * the very last step. `sign_transaction`'s check stays the authoritative
 * backstop regardless, since this one — like any client-side check — could
 * in principle race a lock that fires between this call succeeding and the
 * final "Confirm and send" click.
 *
 * `showStep("send")` runs BEFORE the fallible call, matching the pattern
 * every other function in this file uses (`confirmSend`, `unlock`) — so
 * that if the call fails, the error lands on a screen the user can
 * actually see, rather than in `#send-error` while `#step-send` is still
 * `hidden`.
 *
 * Also checks the active network's `sendSupported` flag before anything
 * else. `updateSendAvailability` already disables the nav button that gets
 * here, so this is defense in depth against a stale/bypassed disabled
 * state, not the primary way a user encounters the restriction — but it
 * still runs first, before the destination list or a single form field is
 * populated, so if it's ever the path that catches it, the message is
 * still the first thing shown, not something reached after filling out a
 * form.
 */
async function goToSend() {
  clearSendState();
  showStep("send");
  const errorEl = el("send-error");
  const network = activeNetwork();

  if (!network.sendSupported) {
    errorEl.textContent = `Sending is not supported on ${network.label} yet.`;
    return;
  }

  try {
    await invoke<string>("get_account_address", { index: activeAccountIndex });
  } catch (error) {
    if (isSessionLockedError(error)) {
      handleSessionLocked();
      return;
    }
    errorEl.textContent = `Could not verify the active account: ${String(error)}`;
    return;
  }

  const select = el<HTMLSelectElement>("send-recipient-select");
  select.replaceChildren();

  const destinations = accounts.filter((a) => a.index !== activeAccountIndex);
  if (destinations.length === 0) {
    errorEl.textContent =
      "No other account is available yet as a destination — this is the only derived account.";
    return;
  }
  for (const account of destinations) {
    const option = document.createElement("option");
    option.value = account.address;
    option.textContent = `Account ${account.index + 1} — ${account.address}`;
    select.appendChild(option);
  }

  const assetSelect = el<HTMLSelectElement>("send-asset-select");
  assetSelect.replaceChildren();
  const nativeOption = document.createElement("option");
  nativeOption.value = NATIVE_ASSET_VALUE;
  nativeOption.textContent = network.nativeCurrencySymbol;
  assetSelect.appendChild(nativeOption);
  for (const token of network.tokens) {
    const option = document.createElement("option");
    option.value = token.address;
    // The list's cosmetic label, not a fetched symbol -- selecting this
    // option is what triggers the real fetch (handleAssetSelectionChanged).
    option.textContent = token.label;
    assetSelect.appendChild(option);
  }
  assetSelect.value = NATIVE_ASSET_VALUE;
}

/**
 * Fired when the send flow's token picker changes. For ETH, this is
 * synchronous and immediate — no network round trip needed. For a token,
 * this is the one and only place a send amount's decimals get fetched: a
 * fresh `fetchTokenMetadata` call every time, never the cached value from
 * `tokenMetadataCache` (that cache exists for the history display, which
 * can tolerate slightly-stale metadata; an amount that's about to be signed
 * and broadcast cannot).
 */
async function handleAssetSelectionChanged() {
  const assetSelect = el<HTMLSelectElement>("send-asset-select");
  const unitEl = el("send-amount-unit");
  const errorEl = el("send-error");
  const value = assetSelect.value;

  if (value === NATIVE_ASSET_VALUE) {
    selectedAsset = null;
    unitEl.textContent = activeNetwork().nativeCurrencySymbol;
    return;
  }

  const tokenAddress = value as Address;
  selectedAsset = null; // Cleared while (re-)fetching, so a stale selection can't be sent.
  unitEl.textContent = "Loading…";
  assetSelect.disabled = true;
  errorEl.textContent = "";

  const rpcUrl = el<HTMLInputElement>("rpc-url").value.trim();
  const network = activeNetwork();
  try {
    const client = rpcClient(network, rpcUrl);
    const metadata = await fetchTokenMetadata(client, tokenAddress);
    tokenMetadataCache.set(tokenCacheKey(network.chainId, tokenAddress), metadata);
    // The selector may have changed again while this fetch was in flight;
    // only apply the result if it's still what's selected.
    if (el<HTMLSelectElement>("send-asset-select").value !== tokenAddress) {
      return;
    }
    selectedAsset = { address: tokenAddress, symbol: metadata.symbol, decimals: metadata.decimals };
    unitEl.textContent = metadata.symbol;
  } catch (error) {
    if (el<HTMLSelectElement>("send-asset-select").value !== tokenAddress) {
      return;
    }
    unitEl.textContent = "";
    errorEl.textContent = `Could not read token info: ${error instanceof Error ? error.message : String(error)}`;
  } finally {
    if (el<HTMLSelectElement>("send-asset-select").value === tokenAddress) {
      assetSelect.disabled = false;
    }
  }
}

/**
 * "Review send": validate the amount, then fetch nonce and fee estimate
 * over the network, and show the mandatory confirmation screen. Each
 * network call is reported distinctly on failure — a nonce-fetch failure
 * and a fee-estimate failure are different operational problems with
 * different likely causes, and collapsing them into one message (the way
 * wrong-passphrase-vs-corrupt-vault deliberately IS collapsed, to avoid a
 * security oracle) would just make this harder to diagnose for no benefit:
 * there is no attacker this ambiguity protects against here.
 */
async function reviewSend() {
  const errorEl = el("send-error");
  const statusEl = el("send-status");
  const reviewBtn = el<HTMLButtonElement>("send-review-btn");
  errorEl.textContent = "";

  const network = activeNetwork();
  // Same defense-in-depth reasoning as goToSend's own check: the nav button
  // and goToSend both already gate this, but a network switch mid-flow
  // (send screen left open, network changed, back to this screen) is a real
  // path that could reach here with a now-unsupported network active.
  if (!network.sendSupported) {
    errorEl.textContent = `Sending is not supported on ${network.label} yet.`;
    return;
  }
  // Custom networks are `sendSupported: true` by default (per this
  // feature's spec) but still can't actually send anything -- see
  // `customNetworkRpcBlockedMessage`'s doc comment.
  if (network.isCustom) {
    errorEl.textContent = customNetworkRpcBlockedMessage(network);
    return;
  }

  const recipientSelect = el<HTMLSelectElement>("send-recipient-select");
  const recipient = recipientSelect.value as Address | "";
  const amountInput = el<HTMLInputElement>("send-amount").value.trim();
  const asset = selectedAsset; // Snapshot: handleAssetSelectionChanged could change it while this runs.

  if (!recipient) {
    errorEl.textContent = "No destination account selected — try leaving and re-entering this screen.";
    return;
  }
  if (el<HTMLSelectElement>("send-asset-select").value !== NATIVE_ASSET_VALUE && !asset) {
    errorEl.textContent = "Still loading token info — wait a moment and try again.";
    return;
  }

  let amountWei = 0n; // Used for the ETH path only; stays zero for a token send (see sign_token_transfer_impl).
  let amountRaw = 0n; // Used for the token path only.
  if (asset === null) {
    try {
      amountWei = parseEtherStrict(amountInput);
    } catch {
      errorEl.textContent = "Enter a valid, positive amount in ETH.";
      return;
    }
    if (amountWei <= 0n) {
      errorEl.textContent = "Amount must be greater than zero.";
      return;
    }
  } else {
    try {
      amountRaw = parseUnitsStrict(amountInput, asset.decimals);
    } catch {
      errorEl.textContent = `Enter a valid, positive amount in ${asset.symbol}.`;
      return;
    }
    if (amountRaw <= 0n) {
      errorEl.textContent = "Amount must be greater than zero.";
      return;
    }
  }

  const rpcUrl = el<HTMLInputElement>("rpc-url").value.trim();
  if (!rpcUrl) {
    errorEl.textContent = "Enter an RPC endpoint URL on the wallet screen first.";
    return;
  }
  let origin: string;
  try {
    origin = new URL(rpcUrl).origin;
  } catch {
    errorEl.textContent = `"${rpcUrl}" is not a valid URL.`;
    return;
  }
  if (origin !== allowedRpcOrigin(network)) {
    errorEl.textContent =
      `This app's security policy only allows ${network.label}'s default endpoint ` +
      `(${network.defaultRpcUrl}) right now.`;
    return;
  }

  reviewBtn.disabled = true;
  const client = rpcClient(network, rpcUrl);

  let nonce: number;
  statusEl.textContent = "Fetching nonce…";
  try {
    // "pending" rather than the default "latest": the nonce to use for a
    // *new* transaction must account for anything already sitting in the
    // mempool for this account, not just what's confirmed on-chain.
    nonce = await client.getTransactionCount({
      address: activeAccountAddress as Address,
      blockTag: "pending",
    });
  } catch (error) {
    statusEl.textContent = "";
    reviewBtn.disabled = false;
    errorEl.textContent = `Could not fetch account nonce: ${error instanceof Error ? error.message : String(error)}`;
    return;
  }

  let maxFeePerGas: bigint;
  let maxPriorityFeePerGas: bigint;
  statusEl.textContent = "Estimating network fees…";
  try {
    const fees = await client.estimateFeesPerGas();
    maxFeePerGas = fees.maxFeePerGas;
    maxPriorityFeePerGas = fees.maxPriorityFeePerGas;
  } catch (error) {
    statusEl.textContent = "";
    reviewBtn.disabled = false;
    errorEl.textContent = `Could not estimate network fees: ${error instanceof Error ? error.message : String(error)}`;
    return;
  }

  let gasLimit: bigint;
  if (asset === null) {
    // A protocol constant for this exact shape of transaction (see
    // ETH_TRANSFER_GAS_LIMIT's own doc comment) -- nothing to estimate.
    gasLimit = ETH_TRANSFER_GAS_LIMIT;
  } else {
    statusEl.textContent = "Estimating gas…";
    try {
      // A contract call costs meaningfully more than a plain transfer and
      // varies by token implementation (e.g. whether the recipient's
      // balance slot was previously zero), so this is a real estimate
      // against the specific call being made -- not the fixed 21000 used
      // for ETH. The calldata built here with viem's own encodeFunctionData
      // is for this estimate only; the transaction that actually gets
      // signed is encoded independently by the Rust backend (see
      // encode_erc20_transfer in lib.rs) via alloy, not derived from this.
      gasLimit = await client.estimateGas({
        account: activeAccountAddress as Address,
        to: asset.address,
        data: encodeFunctionData({
          abi: erc20Abi,
          functionName: "transfer",
          args: [recipient, amountRaw],
        }),
      });
    } catch (error) {
      statusEl.textContent = "";
      reviewBtn.disabled = false;
      errorEl.textContent = `Could not estimate gas: ${error instanceof Error ? error.message : String(error)}`;
      return;
    }
  }

  statusEl.textContent = "";
  reviewBtn.disabled = false;

  const maxFeeTotal = maxFeePerGas * gasLimit;
  el("review-recipient").textContent = recipient;
  el("review-network").textContent = `${network.label} (chain ID ${network.chainId})`;
  el("review-fee").textContent =
    `${formatGwei(maxFeePerGas)} gwei max fee / ${formatGwei(maxPriorityFeePerGas)} gwei ` +
    `max priority fee (gas limit ${gasLimit})`;

  if (asset === null) {
    preparedSend = {
      kind: "eth",
      recipient,
      amountWei,
      nonce,
      maxFeePerGas,
      maxPriorityFeePerGas,
      gasLimit,
    };
    el("review-amount").textContent = `${formatEther(amountWei)} ${network.nativeCurrencySymbol}`;
    el("review-total").textContent =
      `${formatEther(amountWei + maxFeeTotal)} ${network.nativeCurrencySymbol} ` +
      `(amount + worst-case fee; the actual fee charged is usually lower)`;
  } else {
    preparedSend = {
      kind: "token",
      tokenAddress: asset.address,
      tokenSymbol: asset.symbol,
      tokenDecimals: asset.decimals,
      recipient,
      amountRaw,
      nonce,
      maxFeePerGas,
      maxPriorityFeePerGas,
      gasLimit,
    };
    el("review-amount").textContent = `${formatUnits(amountRaw, asset.decimals)} ${asset.symbol}`;
    // No single meaningful "total" here -- the token amount and the native-
    // currency network fee are different assets and can't be summed. Shown
    // separately instead of silently reusing the native-send phrasing
    // (which would have summed a USDC amount with a wei figure into
    // nonsense).
    el("review-total").textContent =
      `${formatEther(maxFeeTotal)} ${network.nativeCurrencySymbol} network fee (worst case), separate from the ` +
      `${formatUnits(amountRaw, asset.decimals)} ${asset.symbol} being sent`;
  }

  el<HTMLInputElement>("send-ack-checkbox").checked = false;
  el<HTMLButtonElement>("send-confirm-btn").disabled = true;
  el("send-confirm-error").textContent = "";
  showStep("send-confirm");
}

/**
 * Parse a decimal ETH string into wei without floating-point math (a
 * `parseFloat`-based conversion loses precision exactly where it matters
 * most: the low-order wei digits of a real monetary amount). Rejects
 * anything that isn't a plain, non-negative decimal number.
 */
function parseEtherStrict(input: string): bigint {
  if (!/^\d+(\.\d+)?$/.test(input)) {
    throw new Error("not a valid decimal amount");
  }
  const [wholePart, fractionPart = ""] = input.split(".");
  const fractionPadded = (fractionPart + "0".repeat(18)).slice(0, 18);
  return BigInt(wholePart) * 10n ** 18n + BigInt(fractionPadded || "0");
}


/**
 * Sign (via the backend, which holds the key), broadcast, then poll for
 * the receipt. Each stage has its own distinct error message — signing,
 * broadcast, and confirmation are different failure modes a user
 * troubleshooting a stuck or rejected send needs to tell apart.
 */
async function confirmSend() {
  if (!preparedSend) {
    return;
  }
  const send = preparedSend;

  const progressEl = el("send-progress");
  const finalErrorEl = el("send-final-error");
  const confirmBtn = el<HTMLButtonElement>("send-confirm-btn");
  finalErrorEl.textContent = "";
  el("send-tx-hash").textContent = "";
  confirmBtn.disabled = true;
  showStep("send-status");

  const rpcUrl = el<HTMLInputElement>("rpc-url").value.trim();
  const network = activeNetwork();
  // Not normally reachable (reviewSend already refuses to prepare a send
  // for a custom network), but checked again here too, same defense-in-
  // depth reasoning as the sendSupported checks elsewhere in this flow.
  if (network.isCustom) {
    finalErrorEl.textContent = customNetworkRpcBlockedMessage(network);
    el("send-done-btn").classList.remove("hidden");
    return;
  }
  const client = rpcClient(network, rpcUrl);

  progressEl.textContent = "Signing…";
  let rawSignedHex: string;
  try {
    // Which backend command signs this depends on the kind of send --
    // sign_transaction for a plain native-currency transfer,
    // sign_token_transfer for an ERC-20 call. Both derive from and sign as
    // whichever account is currently active, not a fixed account — the
    // whole point of the account switcher. `chainId` is the active
    // network's real chain ID, not a hardcoded constant -- the backend's
    // own require_supported_chain_id + require_sendable_chain_id checks
    // are the actual enforcement that a non-sendable network is refused;
    // this value is just reporting the truth to that check, not what makes
    // the restriction hold (the frontend's `network.sendSupported` gate
    // upstream, in goToSend/reviewSend, is what normally prevents reaching
    // this call at all for a mainnet).
    rawSignedHex =
      send.kind === "eth"
        ? await invoke<string>("sign_transaction", {
            to: send.recipient,
            valueWei: send.amountWei.toString(),
            nonce: send.nonce,
            maxFeePerGas: send.maxFeePerGas.toString(),
            maxPriorityFeePerGas: send.maxPriorityFeePerGas.toString(),
            gasLimit: Number(send.gasLimit),
            chainId: network.chainId,
            fromIndex: activeAccountIndex,
          })
        : await invoke<string>("sign_token_transfer", {
            tokenAddress: send.tokenAddress,
            to: send.recipient,
            amountRaw: send.amountRaw.toString(),
            nonce: send.nonce,
            maxFeePerGas: send.maxFeePerGas.toString(),
            maxPriorityFeePerGas: send.maxPriorityFeePerGas.toString(),
            gasLimit: Number(send.gasLimit),
            chainId: network.chainId,
            fromIndex: activeAccountIndex,
          });
  } catch (error) {
    if (isSessionLockedError(error)) {
      handleSessionLocked();
      return;
    }
    progressEl.textContent = "";
    finalErrorEl.textContent = `Signing failed: ${String(error)}`;
    el("send-done-btn").classList.remove("hidden");
    return;
  }

  progressEl.textContent = "Broadcasting…";
  let txHash: `0x${string}`;
  try {
    txHash = await client.sendRawTransaction({
      serializedTransaction: rawSignedHex as `0x${string}`,
    });
  } catch (error) {
    progressEl.textContent = "";
    finalErrorEl.textContent = `Broadcast was rejected: ${error instanceof Error ? error.message : String(error)}`;
    el("send-done-btn").classList.remove("hidden");
    return;
  }

  el("send-tx-hash").textContent = `Transaction hash: ${txHash}`;
  progressEl.textContent = "Pending — waiting for confirmation…";
  try {
    const receipt = await client.waitForTransactionReceipt({
      hash: txHash,
      timeout: 120_000,
    });
    progressEl.textContent =
      receipt.status === "success"
        ? `Confirmed in block ${receipt.blockNumber}.`
        : `Included in block ${receipt.blockNumber}, but the transaction reverted.`;
  } catch (error) {
    // Distinct from a broadcast rejection: the transaction was accepted
    // into the mempool (we have a hash), it just hasn't confirmed within
    // the wait window. It may still confirm later.
    progressEl.textContent = "";
    finalErrorEl.textContent =
      `Confirmation timed out: ${error instanceof Error ? error.message : String(error)}. ` +
      `The transaction may still confirm later — check the hash above.`;
  }

  el("send-done-btn").classList.remove("hidden");
  void fetchBalance();
}

/**
 * Enter the Solana send flow. Unlike `goToSend`, there is no destination
 * dropdown to populate — see `step-solana-send`'s own hint text: this
 * accepts any valid Solana address, not just this wallet's own accounts
 * (deliberately, per this feature's spec). Nothing to prefetch here beyond
 * clearing prior state; `reviewSolanaSend` does the real validation and
 * network calls.
 */
function goToSolanaSend() {
  clearSolanaSendState();
  showStep("solana-send");
}

/**
 * "Review send": validate the recipient and amount, fetch a fresh balance
 * and blockhash, and show the mandatory confirmation screen. Mirrors
 * `reviewSend`'s shape (validate -> fetch over the network -> populate
 * review -> show confirm), simplified for what Solana actually needs: no
 * nonce, no gas estimate, no asset picker -- just a fixed protocol fee
 * (`BASE_FEE_LAMPORTS_PER_SIGNATURE`, not an estimate) and a blockhash.
 */
async function reviewSolanaSend() {
  const errorEl = el("solana-send-error");
  const statusEl = el("solana-send-status");
  const reviewBtn = el<HTMLButtonElement>("solana-send-review-btn");
  errorEl.textContent = "";

  const recipient = el<HTMLInputElement>("solana-send-recipient").value.trim();
  const amountInput = el<HTMLInputElement>("solana-send-amount").value.trim();

  // Real Base58 decode + exact-length check (see `isValidSolanaAddress`'s
  // own doc comment) -- not a regex heuristic, the same bar EVM's EIP-55
  // checksum validation is held to. Checked before any network call, so a
  // typo'd address never gets as far as a balance fetch.
  if (!isValidSolanaAddress(recipient)) {
    errorEl.textContent = "Enter a valid Solana address (Base58, 32 bytes).";
    return;
  }

  let lamports: bigint;
  try {
    lamports = parseUnitsStrict(amountInput, SOL_DECIMALS);
  } catch {
    errorEl.textContent = "Enter a valid, positive amount in SOL.";
    return;
  }
  if (lamports <= 0n) {
    errorEl.textContent = "Amount must be greater than zero.";
    return;
  }

  reviewBtn.disabled = true;
  const account = solanaAccounts.find((a) => a.index === activeSolanaAccountIndex);
  if (!account) {
    errorEl.textContent = "Active Solana account has not been derived yet.";
    reviewBtn.disabled = false;
    return;
  }

  let balanceLamports: bigint;
  statusEl.textContent = "Checking balance…";
  try {
    balanceLamports = await fetchSolanaBalanceLamports(account.address);
  } catch (error) {
    statusEl.textContent = "";
    reviewBtn.disabled = false;
    errorEl.textContent = `Could not fetch balance: ${error instanceof Error ? error.message : String(error)}`;
    return;
  }

  // Must not allow spending more than balance minus the fixed network fee
  // -- checked against a balance just fetched fresh, not a possibly-stale
  // cached value, so a send attempted right after another one already
  // spent this account's balance is judged against the real current state.
  if (lamports + BASE_FEE_LAMPORTS_PER_SIGNATURE > balanceLamports) {
    statusEl.textContent = "";
    reviewBtn.disabled = false;
    errorEl.textContent =
      `Amount plus the ${formatLamportsAsSol(BASE_FEE_LAMPORTS_PER_SIGNATURE)} SOL network fee ` +
      `exceeds the current balance (${formatLamportsAsSol(balanceLamports)} SOL).`;
    return;
  }

  let recentBlockhash: string;
  statusEl.textContent = "Fetching recent blockhash…";
  try {
    recentBlockhash = await fetchLatestBlockhash();
  } catch (error) {
    statusEl.textContent = "";
    reviewBtn.disabled = false;
    errorEl.textContent = `Could not fetch a recent blockhash: ${error instanceof Error ? error.message : String(error)}`;
    return;
  }

  statusEl.textContent = "";
  reviewBtn.disabled = false;

  preparedSolanaSend = { recipient, lamports, recentBlockhash };
  el("solana-review-recipient").textContent = recipient;
  el("solana-review-amount").textContent = `${formatLamportsAsSol(lamports)} SOL`;
  el("solana-review-fee").textContent = `${formatLamportsAsSol(BASE_FEE_LAMPORTS_PER_SIGNATURE)} SOL`;
  el("solana-review-total").textContent =
    `${formatLamportsAsSol(lamports + BASE_FEE_LAMPORTS_PER_SIGNATURE)} SOL (amount + fee)`;

  el<HTMLInputElement>("solana-send-ack-checkbox").checked = false;
  el<HTMLButtonElement>("solana-send-confirm-btn").disabled = true;
  el("solana-send-confirm-error").textContent = "";
  showStep("solana-send-confirm");
}

/**
 * Sign (via the backend, which holds the key), broadcast, then poll for
 * confirmation. Mirrors `confirmSend`'s three distinct failure stages
 * (signing / broadcast / confirmation), the same reasoning: each is a
 * different operational problem a user troubleshooting a stuck or
 * rejected send needs to tell apart.
 */
async function confirmSolanaSend() {
  if (!preparedSolanaSend) {
    return;
  }
  const send = preparedSolanaSend;

  const progressEl = el("solana-send-progress");
  const finalErrorEl = el("solana-send-final-error");
  const confirmBtn = el<HTMLButtonElement>("solana-send-confirm-btn");
  finalErrorEl.textContent = "";
  el("solana-send-signature").textContent = "";
  confirmBtn.disabled = true;
  showStep("solana-send-status");

  progressEl.textContent = "Signing…";
  let signedBase64: string;
  try {
    signedBase64 = await invoke<string>("sign_solana_transaction", {
      to: send.recipient,
      lamports: Number(send.lamports),
      recentBlockhash: send.recentBlockhash,
      fromIndex: activeSolanaAccountIndex,
    });
  } catch (error) {
    if (isSessionLockedError(error)) {
      handleSessionLocked();
      return;
    }
    progressEl.textContent = "";
    finalErrorEl.textContent = `Signing failed: ${String(error)}`;
    el("solana-send-done-btn").classList.remove("hidden");
    return;
  }

  progressEl.textContent = "Broadcasting…";
  let signature: string;
  try {
    signature = await sendRawSolanaTransaction(signedBase64);
  } catch (error) {
    progressEl.textContent = "";
    finalErrorEl.textContent = `Broadcast was rejected: ${error instanceof Error ? error.message : String(error)}`;
    el("solana-send-done-btn").classList.remove("hidden");
    return;
  }

  el("solana-send-signature").textContent = `Signature: ${signature}`;
  progressEl.textContent = "Pending — waiting for confirmation…";
  try {
    const status = await confirmSolanaTransaction(signature);
    progressEl.textContent =
      status === "confirmed" || status === "finalized"
        ? `${status[0].toUpperCase()}${status.slice(1)}.`
        : status === "failed"
          ? "The transaction failed on-chain."
          : "Not yet confirmed within the wait window — it may still confirm later; check the signature above.";
  } catch (error) {
    progressEl.textContent = "";
    finalErrorEl.textContent = `Confirmation check failed: ${error instanceof Error ? error.message : String(error)}. The transaction may still confirm later — check the signature above.`;
  }

  el("solana-send-done-btn").classList.remove("hidden");
  void fetchSolanaBalance();
}

async function unlock() {
  const errorEl = el("unlock-error");
  const statusEl = el("unlock-status");
  const unlockBtn = el<HTMLButtonElement>("unlock-btn");
  errorEl.textContent = "";

  // Same Argon2id cost as sealing, so unlocking is deliberately slow too.
  statusEl.textContent = "Unlocking — this takes a few seconds…";
  unlockBtn.disabled = true;

  try {
    await invoke<string>("unlock_wallet", {
      password: el<HTMLInputElement>("unlock-password").value,
    });
    showStep("unlocked");
    void loadAccounts();
  } catch (error) {
    errorEl.textContent = String(error);
  } finally {
    // Cleared whether the unlock succeeded or failed; a wrong attempt means
    // retyping, which is a small price for not leaving it in the DOM.
    clearPassphraseInputs();
    statusEl.textContent = "";
    unlockBtn.disabled = false;
  }
}

async function lock() {
  await invoke("lock_wallet");
  accounts = [];
  activeAccountIndex = 0;
  activeAccountAddress = null;
  balanceRequestId++; // Invalidate any balance fetch still in flight.
  tokenBalanceRequestId++; // Invalidate any token-balance fetches still in flight.
  txHistoryRequestId++; // Invalidate any tx-history fetch still in flight.
  el("account-list-error").textContent = "";
  el<HTMLSelectElement>("account-select").replaceChildren();
  el("unlocked-address").textContent = "";
  solanaAccounts = [];
  activeSolanaAccountIndex = 0;
  el("solana-account-error").textContent = "";
  el<HTMLSelectElement>("solana-account-select").replaceChildren();
  el("solana-active-address").textContent = "";
  el("solana-add-account-error").textContent = "";
  solanaBalanceRequestId++; // Invalidate any Solana balance fetch still in flight.
  el("solana-balance-value").textContent = "";
  el("solana-balance-value").classList.remove("loading");
  el("solana-balance-error").textContent = "";
  solanaInterstitialAcknowledged = false;
  el("solana-interstitial-address").textContent = "";
  bitcoinAddress = null;
  el("bitcoin-account-error").textContent = "";
  el("bitcoin-active-address").textContent = "";
  bitcoinBalanceRequestId++; // Invalidate any Bitcoin balance fetch still in flight.
  el("bitcoin-balance-value").textContent = "";
  el("bitcoin-balance-value").classList.remove("loading");
  el("bitcoin-balance-error").textContent = "";
  bitcoinInterstitialAcknowledged = false;
  el("bitcoin-interstitial-address").textContent = "";
  switchChainFamily("evm");
  el("balance-value").textContent = "";
  el("balance-value").classList.remove("loading");
  el("balance-error").textContent = "";
  el("token-balance-list").replaceChildren();
  el("tx-history-status").textContent = "";
  el("tx-history-error").textContent = "";
  el("tx-history-empty").classList.add("hidden");
  el("tx-history-list").replaceChildren();
  clearPassphraseInputs();
  clearPhraseFromMemory();
  clearSendState();
  clearSolanaSendState();
  showStep("unlock");
}

window.addEventListener("DOMContentLoaded", async () => {
  renderNetworkSelect();
  el<HTMLInputElement>("rpc-url").value = activeNetwork().defaultRpcUrl;
  renderNetworkBanner();
  updateSendAvailability();
  el<HTMLSelectElement>("network-select").addEventListener("change", (event) => {
    switchNetwork((event.target as HTMLSelectElement).value);
  });
  el("add-custom-network-btn").addEventListener("click", showCustomNetworkForm);
  el("custom-network-cancel-btn").addEventListener("click", hideCustomNetworkForm);
  el("custom-network-add-btn").addEventListener("click", handleAddCustomNetwork);
  el("refresh-balance-btn").addEventListener("click", () => void fetchBalance());
  el("refresh-solana-balance-btn").addEventListener("click", () => void fetchSolanaBalance());
  el<HTMLSelectElement>("solana-account-select").addEventListener("change", (event) => {
    switchActiveSolanaAccount(Number((event.target as HTMLSelectElement).value));
  });
  el("solana-add-account-btn").addEventListener("click", () => void handleAddSolanaAccount());
  el("chain-family-evm-btn").addEventListener("click", () => switchChainFamily("evm"));
  el("chain-family-solana-btn").addEventListener("click", () => switchChainFamily("solana"));
  el("chain-family-bitcoin-btn").addEventListener("click", () => switchChainFamily("bitcoin"));
  el("solana-interstitial-continue-btn").addEventListener("click", () => {
    solanaInterstitialAcknowledged = true;
    el("solana-interstitial").classList.add("hidden");
    el("solana-chain-content").classList.remove("hidden");
  });
  el("bitcoin-interstitial-continue-btn").addEventListener("click", () => {
    bitcoinInterstitialAcknowledged = true;
    el("bitcoin-interstitial").classList.add("hidden");
    el("bitcoin-chain-content").classList.remove("hidden");
  });
  el("refresh-bitcoin-balance-btn").addEventListener("click", () => void fetchBitcoinBalance());
  el("refresh-tx-history-btn").addEventListener("click", () => void fetchTxHistory());
  el<HTMLSelectElement>("account-select").addEventListener("change", (event) => {
    switchActiveAccount(Number((event.target as HTMLSelectElement).value));
  });

  el("generate-btn").addEventListener("click", generatePhrase);
  el("backup-done-btn").addEventListener("click", startConfirmation);
  el("confirm-btn").addEventListener("click", confirmAndSeal);
  el("reset-selection-btn").addEventListener("click", () => {
    selectedSlots = [];
    el("confirm-error").textContent = "";
    renderConfirmation();
  });
  el("unlock-btn").addEventListener("click", unlock);
  el("lock-btn").addEventListener("click", lock);
  el("reveal-nav-btn").addEventListener("click", () => showStep("reveal"));
  el("reveal-back-btn").addEventListener("click", () => showStep("unlocked"));
  el("reveal-phrase-btn").addEventListener("click", () => {
    el("reveal-phrase-auth").classList.remove("hidden");
  });
  el("reveal-phrase-cancel-btn").addEventListener("click", () => {
    el("reveal-phrase-auth").classList.add("hidden");
    el<HTMLInputElement>("reveal-phrase-password").value = "";
    el("reveal-phrase-error").textContent = "";
  });
  el("reveal-phrase-confirm-btn").addEventListener("click", () => void handleRevealPhraseConfirm());
  el("reveal-phrase-hide-btn").addEventListener("click", () => {
    el("reveal-phrase-words").replaceChildren();
    el("reveal-phrase-words").classList.add("hidden");
    el("reveal-phrase-hide-btn").classList.add("hidden");
  });
  el("export-key-btn").addEventListener("click", () => {
    el("export-key-auth").classList.remove("hidden");
  });
  el("export-key-cancel-btn").addEventListener("click", () => {
    el("export-key-auth").classList.add("hidden");
    el<HTMLInputElement>("export-key-password").value = "";
    el("export-key-error").textContent = "";
  });
  el("export-key-confirm-btn").addEventListener("click", () => void handleExportKeyConfirm());
  el("export-key-hide-btn").addEventListener("click", () => {
    el("export-key-value").textContent = "";
    el("export-key-value").classList.add("hidden");
    el("export-key-label").textContent = "";
    el("export-key-label").classList.add("hidden");
    el("export-key-hide-btn").classList.add("hidden");
  });
  el("to-unlock-btn").addEventListener("click", () => {
    clearPhraseFromMemory();
    clearPassphraseInputs();
    showStep("unlock");
  });

  el("send-nav-btn").addEventListener("click", () => void goToSend());
  el("send-cancel-btn").addEventListener("click", () => {
    clearSendState();
    showStep("unlocked");
  });
  el("send-asset-select").addEventListener("change", () => void handleAssetSelectionChanged());
  el("send-review-btn").addEventListener("click", () => void reviewSend());
  el("send-back-btn").addEventListener("click", () => {
    el("send-confirm-error").textContent = "";
    showStep("send");
  });
  el<HTMLInputElement>("send-ack-checkbox").addEventListener("change", (event) => {
    el<HTMLButtonElement>("send-confirm-btn").disabled = !(
      event.target as HTMLInputElement
    ).checked;
  });
  // Deliberately does NOT call confirmSend() itself -- that only ever
  // happens from the explicit Confirm button click below, never as a side
  // effect of checking the acknowledgment box.
  el("send-confirm-btn").addEventListener("click", () => void confirmSend());
  el("send-done-btn").addEventListener("click", () => {
    clearSendState();
    showStep("unlocked");
    void fetchBalance();
  });

  el("solana-send-nav-btn").addEventListener("click", goToSolanaSend);
  el("solana-send-cancel-btn").addEventListener("click", () => {
    clearSolanaSendState();
    showStep("unlocked");
  });
  el("solana-send-review-btn").addEventListener("click", () => void reviewSolanaSend());
  el("solana-send-back-btn").addEventListener("click", () => {
    el("solana-send-confirm-error").textContent = "";
    showStep("solana-send");
  });
  el<HTMLInputElement>("solana-send-ack-checkbox").addEventListener("change", (event) => {
    el<HTMLButtonElement>("solana-send-confirm-btn").disabled = !(event.target as HTMLInputElement).checked;
  });
  // Deliberately does NOT call confirmSolanaSend() itself -- same reasoning
  // as the EVM ack checkbox above: only the explicit Confirm button click
  // triggers a real send.
  el("solana-send-confirm-btn").addEventListener("click", () => void confirmSolanaSend());
  el("solana-send-done-btn").addEventListener("click", () => {
    clearSolanaSendState();
    showStep("unlocked");
    void fetchSolanaBalance();
  });

  el("unlock-password").addEventListener("keydown", (event) => {
    if ((event as KeyboardEvent).key === "Enter") {
      unlock();
    }
  });

  // An existing vault means there is nothing to create — go straight to
  // unlock rather than offering a create flow that would be refused.
  showStep((await invoke<boolean>("wallet_exists")) ? "unlock" : "setup");
});
