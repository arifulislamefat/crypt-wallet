import { invoke } from "@tauri-apps/api/core";
import { formatEther } from "viem";
import {
  ALLOWED_RPC_ORIGINS,
  DEFAULT_SEPOLIA_RPC_URL,
  sepoliaClient,
  type Address,
} from "./sepolia";

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
  | "done";

const ALL_STEPS: Step[] = [
  "unlock",
  "unlocked",
  "setup",
  "backup",
  "confirm",
  "done",
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
  el("unlock-password").addEventListener("keydown", (event) => {
    if ((event as KeyboardEvent).key === "Enter") {
      unlock();
    }
  });

  // An existing vault means there is nothing to create — go straight to
  // unlock rather than offering a create flow that would be refused.
  showStep((await invoke<boolean>("wallet_exists")) ? "unlock" : "setup");
});
