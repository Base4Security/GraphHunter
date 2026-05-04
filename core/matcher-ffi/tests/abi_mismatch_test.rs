//! Fase 2 — ABI compatibility guard tests.
//!
//! The production path calls [`ensure_abi_compatible`] through a
//! `std::sync::Once`, so a synthetic mismatch cannot be triggered
//! twice in the same process. We test the pure logic via
//! [`check_abi_compat`] instead — same equality check, no one-shot
//! guard. The runtime guard is covered separately by
//! `test_runtime_abi_matches_expected` below, which confirms the
//! linked library advertises the version this crate knows.

#![cfg(feature = "simd")]

use graph_hunter_matcher_ffi::ffi;

/// Positive path: matching versions produce `Ok(())`.
#[test]
fn check_abi_compat_accepts_matching_versions() {
    assert!(ffi::check_abi_compat(1, 1).is_ok());
    assert!(ffi::check_abi_compat(42, 42).is_ok());
    assert!(ffi::check_abi_compat(0, 0).is_ok());
}

/// Synthetic mismatch: a differing `got` must return a typed `Err`
/// whose message names both the linked and expected versions. This is
/// the check that would (via `panic!` on `Err`) abort process startup
/// in production — here we just read the message.
#[test]
fn check_abi_compat_rejects_mismatch_with_informative_error() {
    let err = ffi::check_abi_compat(999, 1).expect_err("mismatch must not be Ok");
    assert!(
        err.contains("v999"),
        "error message must cite the lib-reported version: {err}"
    );
    assert!(
        err.contains("v1"),
        "error message must cite the expected version: {err}"
    );
    assert!(
        err.to_lowercase().contains("abi mismatch"),
        "error must label itself as an ABI mismatch: {err}"
    );
}

/// Edge cases: zero on either side must still be detected as mismatch.
/// Guards against a future refactor that special-cases 0 as "unknown".
#[test]
fn check_abi_compat_zero_is_not_a_wildcard() {
    assert!(ffi::check_abi_compat(0, 1).is_err());
    assert!(ffi::check_abi_compat(1, 0).is_err());
}

/// The *real* linked library must advertise the version this crate
/// was built against. Regression gate for header/binary drift — if
/// someone bumps `GM_ABI_VERSION` without also bumping
/// `EXPECTED_ABI_VERSION` (or vice versa) this test fails before any
/// matcher operation runs.
#[test]
fn runtime_abi_matches_expected() {
    assert_eq!(
        ffi::abi_version(),
        ffi::expected_abi_version(),
        "linked libgraphmatch reports a different ABI than this crate expects"
    );
}
