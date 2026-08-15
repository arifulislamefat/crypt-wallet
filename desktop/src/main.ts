import { invoke } from "@tauri-apps/api/core";

let healthCheckBtnEl: HTMLButtonElement | null;
let healthCheckMsgEl: HTMLElement | null;

async function runCoreHealthCheck() {
  if (healthCheckMsgEl) {
    healthCheckMsgEl.textContent = await invoke("core_health_check");
  }
}

window.addEventListener("DOMContentLoaded", () => {
  healthCheckBtnEl = document.querySelector("#health-check-btn");
  healthCheckMsgEl = document.querySelector("#health-check-msg");
  healthCheckBtnEl?.addEventListener("click", () => {
    runCoreHealthCheck();
  });
});
