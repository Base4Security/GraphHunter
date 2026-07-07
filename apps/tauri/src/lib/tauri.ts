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

/** Extract a displayable string from any caught error (including CommandError objects). */
export function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "string") return e;
  if (e && typeof e === "object") {
    const obj = e as Record<string, unknown>;
    if (typeof obj.message === "string") return obj.message;
    if (typeof obj.kind === "string" && typeof obj.message === "string")
      return obj.message;
  }
  return String(e);
}
