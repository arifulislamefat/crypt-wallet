import { invoke } from "@tauri-apps/api/core";

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
    el("unlocked-address").textContent = address;
    showStep("unlocked");
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
  el("unlocked-address").textContent = "";
  clearPassphraseInputs();
  clearPhraseFromMemory();
  showStep("unlock");
}

window.addEventListener("DOMContentLoaded", async () => {
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
