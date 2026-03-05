/**
 * Runtime detection: Tauri desktop vs browser.
 */

declare global {
  interface Window {
    __TAURI__?: unknown;
    __TAURI_INTERNALS__?: unknown;
  }
}

export function isTauri(): boolean {
  if (typeof window === "undefined") return false;
  return !!(window.__TAURI_INTERNALS__ ?? window.__TAURI__);
}
