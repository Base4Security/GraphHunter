//! Cooperative cancellation for pattern searches.
//!
//! A search runs synchronously under the graph's read lock, so a caller
//! that stops waiting (an HTTP timeout, say) does not stop the search:
//! it keeps a core busy and keeps the lock, and any writer queued behind
//! it stalls every later reader. A [`CancelToken`] lets the caller end
//! the search for real.
//!
//! The token travels through a thread-local rather than through the
//! search signatures: [`scope`] installs it on the calling thread, the
//! search entry points pick it up with [`current`] and hand it explicitly
//! to the DFS loops (including the ones running on rayon workers, which
//! do not inherit thread-locals).
//!
//! Covered: the plain DFS, its AMAC variant and the anomaly-guided DFS.
//! The LFTJ / Yannakakis / gapped operators do not poll the token yet.

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Shared flag a search polls once per DFS frame.
#[derive(Clone, Debug, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask every search holding this token to stop at its next frame.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    pub(crate) fn flag(&self) -> &AtomicBool {
        &self.0
    }
}

thread_local! {
    static CURRENT: RefCell<Option<CancelToken>> = const { RefCell::new(None) };
}

/// Run `f` with `token` as this thread's cancellation token. Searches
/// started inside `f` stop early once the token is cancelled; what they
/// return then is a partial result the caller must discard (check
/// [`CancelToken::is_cancelled`] afterwards).
pub fn scope<R>(token: &CancelToken, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<CancelToken>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CURRENT.with(|c| *c.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(CURRENT.with(|c| c.borrow_mut().replace(token.clone())));
    f()
}

/// The token installed by the enclosing [`scope`], or one that is never
/// cancelled when there is none.
pub(crate) fn current() -> CancelToken {
    CURRENT.with(|c| c.borrow().clone()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_installs_and_restores() {
        let outer = CancelToken::new();
        let inner = CancelToken::new();
        inner.cancel();
        scope(&outer, || {
            assert!(!current().is_cancelled());
            scope(&inner, || assert!(current().is_cancelled()));
            // Back to the outer token once the inner scope ends.
            assert!(!current().is_cancelled());
            outer.cancel();
            assert!(current().is_cancelled());
        });
        // No scope: a fresh token that nobody can cancel.
        assert!(!current().is_cancelled());
    }
}
