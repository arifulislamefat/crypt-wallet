import { invoke } from "@tauri-apps/api/core";
import { formatEther, formatGwei } from "viem";
import {
  ALLOWED_RPC_ORIGINS,
  DEFAULT_SEPOLIA_RPC_URL,
  SEPOLIA_CHAIN_ID,
  sepoliaClient,
  type Address,
} from "./sepolia";

/**
 * Fixed intrinsic gas cost of a plain ETH transfer to an externally-owned
 * account (no contract call, no calldata) — a protocol constant (EIP-2's
 * G_transaction base cost), not an estimate. Account 2 of this wallet is
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
  | "send-status";

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
 * The unlocked wallet's account-0 address — public data, freely usable for
 * a read-only balance query. Set on unlock, cleared on lock.
 */
let unlockedAddress: Address | null = null;

/**
 * Bumped at the start of every balance fetch; a response only gets applied
 * if it's still the most recent request. Without this, clicking refresh
 * twice — or changing the RPC endpoint and refetching before the first
 * request has failed — could let a slow, stale response land *after* a
 * newer one and silently overwrite it, which is exactly the "stale balance
 * shown as if it were current" failure mode this feature must avoid.
 */
let balanceRequestId = 0;

/**
 * Send-flow state, gathered on "Review send" and consumed on "Confirm and
 * send". All public data (a recipient address, an amount, network fee
 * fields) — nothing here is secret, unlike the phrase/passphrase state
 * above. Reset (`clearSendState`) on cancel, on returning to the wallet
 * after a send, and on lock.
 */
interface PreparedSend {
  recipient: Address;
  amountWei: bigint;
  amountEthDisplay: string;
  nonce: number;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}
let preparedSend: PreparedSend | null = null;

function clearSendState() {
  preparedSend = null;
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

/**
 * Exact error string the backend returns from `get_second_account_address`
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
 * Fetch and render the Sepolia ETH balance for `unlockedAddress`, using
 * whatever RPC URL is currently in the override field.
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

  if (!unlockedAddress) {
    return;
  }

  const requestId = ++balanceRequestId;
  errorEl.textContent = "";

  if (!rpcUrl) {
    errorEl.textContent = "Enter an RPC endpoint URL.";
    return;
  }

  // Checked before touching the network at all — not by reacting to a CSP
  // violation after the fact. See ALLOWED_RPC_ORIGINS's doc comment: a
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
  if (!ALLOWED_RPC_ORIGINS.has(origin)) {
    errorEl.textContent =
      `This app's security policy only allows the default Sepolia endpoint ` +
      `(${DEFAULT_SEPOLIA_RPC_URL}) right now. "${rpcUrl}" would be blocked.`;
    return;
  }

  // Loading state: explicit, not just leaving the previous value on screen.
  // A balance that's actually stale (mid-refresh, or left over from before
  // an error) must never be visually indistinguishable from a fresh one.
  valueEl.textContent = "Loading balance…";
  valueEl.classList.add("loading");
  refreshBtn.disabled = true;

  try {
    const balanceWei = await sepoliaClient(rpcUrl).getBalance({
      address: unlockedAddress,
    });

    if (requestId !== balanceRequestId) {
      return; // Superseded by a newer request; drop this result.
    }
    valueEl.textContent = `${formatEther(balanceWei)} ETH`;
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
    // ALLOWED_RPC_ORIGINS check above before this try block starts. This is
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
 * Enter the send flow: fetch account 2's address (an IPC call, no network)
 * and show the amount-entry screen.
 *
 * `showStep("send")` runs BEFORE the fallible call, matching the pattern
 * every other function in this file uses (`confirmSend`, `unlock`) — so
 * that if the call fails, the error lands on a screen the user can
 * actually see. The previous version called `showStep` only on success,
 * which meant a failure wrote its message into `#send-error` while
 * `#step-send` was still `hidden`: the click appeared to do nothing at
 * all, indistinguishable from a broken button.
 */
async function goToSend() {
  clearSendState();
  showStep("send");
  const errorEl = el("send-error");
  try {
    const recipient = await invoke<string>("get_second_account_address");
    el("send-recipient").textContent = recipient;
  } catch (error) {
    if (isSessionLockedError(error)) {
      handleSessionLocked();
      return;
    }
    errorEl.textContent = `Could not derive the recipient account: ${String(error)}`;
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

  const recipient = el("send-recipient").textContent as Address | "";
  const amountInput = el<HTMLInputElement>("send-amount").value.trim();

  if (!recipient) {
    errorEl.textContent = "No recipient address — try leaving and re-entering this screen.";
    return;
  }

  let amountWei: bigint;
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
  if (!ALLOWED_RPC_ORIGINS.has(origin)) {
    errorEl.textContent =
      `This app's security policy only allows the default Sepolia endpoint ` +
      `(${DEFAULT_SEPOLIA_RPC_URL}) right now.`;
    return;
  }

  reviewBtn.disabled = true;
  const client = sepoliaClient(rpcUrl);

  let nonce: number;
  statusEl.textContent = "Fetching nonce…";
  try {
    // "pending" rather than the default "latest": the nonce to use for a
    // *new* transaction must account for anything already sitting in the
    // mempool for this account, not just what's confirmed on-chain.
    nonce = await client.getTransactionCount({
      address: unlockedAddress as Address,
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

  statusEl.textContent = "";
  reviewBtn.disabled = false;

  preparedSend = {
    recipient,
    amountWei,
    amountEthDisplay: formatEther(amountWei),
    nonce,
    maxFeePerGas,
    maxPriorityFeePerGas,
  };

  el("review-recipient").textContent = recipient;
  el("review-amount").textContent = `${preparedSend.amountEthDisplay} ETH`;
  const maxFeeTotal = maxFeePerGas * ETH_TRANSFER_GAS_LIMIT;
  el("review-fee").textContent =
    `${formatGwei(maxFeePerGas)} gwei max fee / ${formatGwei(maxPriorityFeePerGas)} gwei ` +
    `max priority fee (gas limit ${ETH_TRANSFER_GAS_LIMIT})`;
  el("review-total").textContent =
    `${formatEther(amountWei + maxFeeTotal)} ETH (amount + worst-case fee; the actual fee charged is usually lower)`;

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
  const { recipient, amountWei, nonce, maxFeePerGas, maxPriorityFeePerGas } = preparedSend;

  const progressEl = el("send-progress");
  const finalErrorEl = el("send-final-error");
  const confirmBtn = el<HTMLButtonElement>("send-confirm-btn");
  finalErrorEl.textContent = "";
  el("send-tx-hash").textContent = "";
  confirmBtn.disabled = true;
  showStep("send-status");

  const rpcUrl = el<HTMLInputElement>("rpc-url").value.trim();
  const client = sepoliaClient(rpcUrl);

  progressEl.textContent = "Signing…";
  let rawSignedHex: string;
  try {
    rawSignedHex = await invoke<string>("sign_transaction", {
      to: recipient,
      valueWei: amountWei.toString(),
      nonce,
      maxFeePerGas: maxFeePerGas.toString(),
      maxPriorityFeePerGas: maxPriorityFeePerGas.toString(),
      gasLimit: Number(ETH_TRANSFER_GAS_LIMIT),
      chainId: SEPOLIA_CHAIN_ID,
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

async function unlock() {
  const errorEl = el("unlock-error");
  const statusEl = el("unlock-status");
  const unlockBtn = el<HTMLButtonElement>("unlock-btn");
  errorEl.textContent = "";

  // Same Argon2id cost as sealing, so unlocking is deliberately slow too.
  statusEl.textContent = "Unlocking — this takes a few seconds…";
  unlockBtn.disabled = true;

  try {
    const address = await invoke<string>("unlock_wallet", {
      password: el<HTMLInputElement>("unlock-password").value,
    });
    unlockedAddress = address as Address;
    el("unlocked-address").textContent = address;
    showStep("unlocked");
    void fetchBalance();
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
  unlockedAddress = null;
  balanceRequestId++; // Invalidate any balance fetch still in flight.
  el("unlocked-address").textContent = "";
  el("balance-value").textContent = "";
  el("balance-value").classList.remove("loading");
  el("balance-error").textContent = "";
  clearPassphraseInputs();
  clearPhraseFromMemory();
  clearSendState();
  showStep("unlock");
}

window.addEventListener("DOMContentLoaded", async () => {
  el<HTMLInputElement>("rpc-url").value = DEFAULT_SEPOLIA_RPC_URL;
  el("refresh-balance-btn").addEventListener("click", () => void fetchBalance());

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
  el("unlock-password").addEventListener("keydown", (event) => {
    if ((event as KeyboardEvent).key === "Enter") {
      unlock();
    }
  });

  // An existing vault means there is nothing to create — go straight to
  // unlock rather than offering a create flow that would be refused.
  showStep((await invoke<boolean>("wallet_exists")) ? "unlock" : "setup");
});
