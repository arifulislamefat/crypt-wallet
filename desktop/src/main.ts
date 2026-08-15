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
 * only the ordering the user clicked. Cleared as soon as the wallet is
 * sealed (see `clearPhraseFromMemory`).
 */
let phraseWords: string[] = [];
/** Indices into `phraseWords`, in the order the user has clicked them. */
let selectedIndices: number[] = [];
/** The shuffled word bank: indices into `phraseWords`, in display order. */
let bankOrder: number[] = [];

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

function shuffled(values: number[]): number[] {
  const out = [...values];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

/**
 * Drop our references to the phrase. JavaScript gives no way to actually
 * scrub the underlying string memory — the real guarantee lives on the Rust
 * side, where the mnemonic is zeroized on drop. This just makes sure the UI
 * isn't holding a copy any longer than the flow requires.
 */
function clearPhraseFromMemory() {
  phraseWords = [];
  selectedIndices = [];
  bankOrder = [];
  el("phrase-list").replaceChildren();
  el("word-bank").replaceChildren();
  el("selected-words").replaceChildren();
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
  const password = el<HTMLInputElement>("password").value;
  const passwordConfirm = el<HTMLInputElement>("password-confirm").value;

  if (characterCount(password) < MIN_PASSWORD_LENGTH) {
    errorEl.textContent = `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
    return;
  }
  if (password !== passwordConfirm) {
    errorEl.textContent = "Passwords do not match.";
    return;
  }

  try {
    phraseWords = await invoke<string[]>("generate_new_mnemonic", {
      wordCount,
    });
  } catch (error) {
    errorEl.textContent = String(error);
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
  selectedIndices = [];
  bankOrder = shuffled(phraseWords.map((_, index) => index));
  renderConfirmation();
  showStep("confirm");
}

function renderConfirmation() {
  const selectedList = el("selected-words");
  selectedList.replaceChildren();
  for (const index of selectedIndices) {
    const item = document.createElement("li");
    item.textContent = phraseWords[index];
    selectedList.appendChild(item);
  }

  const bank = el("word-bank");
  bank.replaceChildren();
  for (const index of bankOrder) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = phraseWords[index];
    // Track by index, not by text: a BIP-39 phrase can legitimately repeat
    // a word, and each occurrence has to be selectable exactly once.
    button.disabled = selectedIndices.includes(index);
    button.addEventListener("click", () => {
      selectedIndices.push(index);
      el("confirm-error").textContent = "";
      renderConfirmation();
    });
    bank.appendChild(button);
  }

  el("confirm-btn").toggleAttribute(
    "disabled",
    selectedIndices.length !== phraseWords.length,
  );
}

async function confirmAndSeal() {
  const errorEl = el("confirm-error");
  const statusEl = el("confirm-status");
  const confirmBtn = el<HTMLButtonElement>("confirm-btn");
  errorEl.textContent = "";

  // Argon2id at the desktop cost parameters takes several seconds by
  // design, and it blocks this call. Say so, and don't let the user
  // double-submit while it runs.
  statusEl.textContent = "Encrypting your wallet — this takes a few seconds…";
  confirmBtn.disabled = true;

  try {
    const address = await invoke<string>("confirm_and_seal_wallet", {
      // Only the user's chosen ordering goes back across the bridge. The
      // backend compares it against the phrase it already holds.
      selectedWords: selectedIndices.map((index) => phraseWords[index]),
      password: el<HTMLInputElement>("password").value,
    });

    clearPhraseFromMemory();
    el<HTMLInputElement>("password").value = "";
    el<HTMLInputElement>("password-confirm").value = "";

    el("address").textContent = address;
    showStep("done");
  } catch (error) {
    errorEl.textContent = String(error);
    // Let the user retry the ordering; the backend keeps the phrase pending
    // on a mismatch precisely so a mis-click isn't fatal.
    selectedIndices = [];
    renderConfirmation();
  } finally {
    statusEl.textContent = "";
    confirmBtn.disabled = false;
  }
}

async function unlock() {
  const errorEl = el("unlock-error");
  const statusEl = el("unlock-status");
  const unlockBtn = el<HTMLButtonElement>("unlock-btn");
  const passwordEl = el<HTMLInputElement>("unlock-password");
  errorEl.textContent = "";

  // Same Argon2id cost as sealing, so unlocking is deliberately slow too.
  statusEl.textContent = "Unlocking — this takes a few seconds…";
  unlockBtn.disabled = true;

  try {
    const address = await invoke<string>("unlock_wallet", {
      password: passwordEl.value,
    });
    passwordEl.value = "";
    el("unlocked-address").textContent = address;
    showStep("unlocked");
  } catch (error) {
    errorEl.textContent = String(error);
  } finally {
    statusEl.textContent = "";
    unlockBtn.disabled = false;
  }
}

async function lock() {
  await invoke("lock_wallet");
  el("unlocked-address").textContent = "";
  el<HTMLInputElement>("unlock-password").value = "";
  showStep("unlock");
}

window.addEventListener("DOMContentLoaded", async () => {
  el("generate-btn").addEventListener("click", generatePhrase);
  el("backup-done-btn").addEventListener("click", startConfirmation);
  el("confirm-btn").addEventListener("click", confirmAndSeal);
  el("reset-selection-btn").addEventListener("click", () => {
    selectedIndices = [];
    el("confirm-error").textContent = "";
    renderConfirmation();
  });
  el("unlock-btn").addEventListener("click", unlock);
  el("lock-btn").addEventListener("click", lock);
  el("to-unlock-btn").addEventListener("click", () => showStep("unlock"));
  el("unlock-password").addEventListener("keydown", (event) => {
    if ((event as KeyboardEvent).key === "Enter") {
      unlock();
    }
  });

  // An existing vault means there is nothing to create — go straight to
  // unlock rather than offering a create flow that would be refused.
  showStep((await invoke<boolean>("wallet_exists")) ? "unlock" : "setup");
});
