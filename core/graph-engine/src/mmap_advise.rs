//! Hint the kernel that an `Mmap` region is a good candidate for transparent
//! huge pages (THP). Linux-only; a no-op stub everywhere else.
//!
//! Gated behind the `GRAPHHUNTER_HUGEPAGES=1` env var because the trade is
//! workload-dependent:
//!   * Huge pages cut TLB misses on large mmaps (the spill store's merged
//!     file regularly sweeps multi-GB ranges during k-way merge / lookup),
//!     but they pessimize tiny mmaps where the 2 MiB page granularity
//!     wastes RSS.
//!   * THP requires the kernel to have it enabled
//!     (`/sys/kernel/mm/transparent_hugepage/enabled` set to `madvise` or
//!     `always`); a hardened kernel may have it off entirely, in which
//!     case `madvise` is harmless but useless.
//!   * The `MADV_HUGEPAGE` symbol is Linux-specific. Windows has no
//!     `madvise` syscall; macOS exposes huge-page semantics through other
//!     APIs but not under the `MADV_HUGEPAGE` name. The non-Linux stub
//!     below keeps the call sites portable.
//!
//! The env var is read once per call rather than cached at startup. The
//! check is a single `var_os` hash lookup — measurable only inside a hot
//! loop, and `Mmap::map` itself is always at least one syscall, so the
//! overhead is dominated by the surrounding I/O.
//!
//! Trade noted in the BlackHat Arsenal 2026 perf push (Bucket B, unit B8):
//! estimated 10–30% TLB-stall reduction on Linux for graphs that exceed L2,
//! dormant on the Windows dev host and on any deploy where the env var
//! isn't set.

/// Advise the kernel that `mmap` should prefer transparent huge pages,
/// if `GRAPHHUNTER_HUGEPAGES=1` is set in the environment. Linux-only.
#[cfg(target_os = "linux")]
pub fn try_hugepages(mmap: &memmap2::Mmap) {
    if std::env::var_os("GRAPHHUNTER_HUGEPAGES").is_none() {
        return;
    }
    // Safety: `mmap.as_ptr()` and `mmap.len()` describe a valid mapped
    // region for the lifetime of `mmap`. `MADV_HUGEPAGE` is a hint and
    // never invalidates or relocates the mapping. Errors (EINVAL on a
    // kernel without THP, EAGAIN under memory pressure) are silently
    // ignored — the env gate is opt-in, so a missed advise is benign.
    unsafe {
        let _ = libc::madvise(
            mmap.as_ptr() as *mut libc::c_void,
            mmap.len(),
            libc::MADV_HUGEPAGE,
        );
    }
}

#[cfg(not(target_os = "linux"))]
pub fn try_hugepages(_mmap: &memmap2::Mmap) {}
