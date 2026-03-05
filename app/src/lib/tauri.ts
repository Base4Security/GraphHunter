/**
 * Safe Tauri invoke: only calls the real API when running inside Tauri.
 * In the browser (web build), rejects so callers can catch and avoid "undefined.invoke" crash.
 */

import { isTauri } from "./runtime";

export async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauri()) {
    return Promise.reject(new Error("Graph Hunter desktop features require the Tauri app. Run with: npm run tauri dev"));
  }
  const { invoke: tauriInvoke } = await import("@tauri-apps/api/core");
  return tauriInvoke<T>(cmd, args ?? {});
}
