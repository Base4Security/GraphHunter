/** Returns current time as HH:MM:SS for log entries. */
export function now(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}
