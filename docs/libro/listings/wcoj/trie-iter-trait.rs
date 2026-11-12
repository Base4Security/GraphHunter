pub trait TrieIter {
    /// True if the cursor is past the end of the current level. Once
    /// at end, `key` is undefined; call `up` to ascend or restart.
    fn at_end(&self) -> bool;

    /// Read the current key at this level. Precondition: `!at_end()`.
    fn key(&self) -> u64;

    /// Advance to the next key at this level. May set `at_end` true.
    fn next(&mut self);

    /// Advance forward to the smallest key `>= target` at this level.
    /// May set `at_end` true if no such key exists. The classic
    /// leapfrog optimization is exponential gallop + binary search;
    /// the reference implementation here uses linear scan because the
    /// initial use sites are small. SIMD acceleration (galloping
    /// intersection à la Schlegel/Lemire) goes here.
    fn seek(&mut self, target: u64);

    /// Descend one level. The level below is rooted at the current
    /// `key` of this level. Precondition: `!at_end()`. Postcondition:
    /// the new level's cursor is at its first key.
    fn open(&mut self);

    /// Ascend one level. Restores the cursor at the parent level to
    /// the position it had before `open`.
    fn up(&mut self);
}
