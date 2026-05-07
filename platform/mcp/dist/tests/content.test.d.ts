/**
 * Regression test for the v2 long-text truncation bug (#2 from the
 * 2026-05-06 QA pass): `safeJsonContent` was cutting every string
 * > 200 chars with " ... " regardless of key, destroying
 * payload-bearing fields like `narrative`, `yaml`, `content`,
 * `vrl_source`, etc. Fix: key-aware whitelist (`LONG_TEXT_KEYS`).
 *
 * These tests pin the contract: long-text keys round-trip unchanged,
 * unknown long strings still get truncated.
 */
export {};
//# sourceMappingURL=content.test.d.ts.map