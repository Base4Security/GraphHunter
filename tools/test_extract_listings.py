"""
Tests for extract-listings.py — verifies snippet extraction and ref checking.
Run with: pytest tools/test_extract_listings.py -v
Or simply: python3 tools/test_extract_listings.py
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).parent / "extract-listings.py"


def run_extractor(repo_root: Path, out: Path, check: bool = False) -> subprocess.CompletedProcess:
    """Run the extract-listings.py script and return result."""
    args = [sys.executable, str(SCRIPT), "--repo-root", str(repo_root), "--out", str(out)]
    if check:
        args.append("--check")
    return subprocess.run(args, capture_output=True, text=True)


def make_repo(tmp: Path) -> Path:
    """Create a minimal fake repo structure under tmp."""
    (tmp / "src").mkdir()
    (tmp / "docs" / "libro").mkdir(parents=True)
    return tmp


def test_no_snippets_empty_repo():
    """Empty repo should extract zero snippets and exit 0."""
    with tempfile.TemporaryDirectory() as td:
        repo = make_repo(Path(td))
        out = Path(td) / "listings"
        r = run_extractor(repo, out)
        assert r.returncode == 0, f"stderr={r.stderr}"
        assert "Extra" in r.stdout  # "Extraídos 0 snippets..."


def test_extracts_single_snippet():
    """A single @book-snippet block should be extracted to listings/NAME.rs."""
    with tempfile.TemporaryDirectory() as td:
        repo = make_repo(Path(td))
        (repo / "src" / "lib.rs").write_text(
            "fn foo() {}\n"
            "// @book-snippet:my-snippet\n"
            "pub fn bar() -> u32 { 42 }\n"
            "// @book-snippet-end\n"
            "fn baz() {}\n",
            encoding="utf-8",
        )
        out = repo / "out"
        r = run_extractor(repo, out)
        assert r.returncode == 0, r.stderr
        snippet_file = out / "my-snippet.rs"
        assert snippet_file.exists()
        assert "pub fn bar() -> u32 { 42 }" in snippet_file.read_text(encoding="utf-8")


def test_check_mode_passes_with_no_refs():
    """--check on empty .tex tree should pass."""
    with tempfile.TemporaryDirectory() as td:
        repo = make_repo(Path(td))
        out = repo / "out"
        r = run_extractor(repo, out, check=True)
        assert r.returncode == 0, r.stderr
        assert "OK" in r.stdout


def test_check_mode_fails_on_missing_ref():
    """--check should exit non-zero if .tex references a nonexistent snippet."""
    with tempfile.TemporaryDirectory() as td:
        repo = make_repo(Path(td))
        (repo / "docs" / "libro" / "chapter1.tex").write_text(
            "\\inputminted{rust}{listings/nonexistent.rs}\n",
            encoding="utf-8",
        )
        out = repo / "out"
        r = run_extractor(repo, out, check=True)
        assert r.returncode == 1, f"expected exit 1, got {r.returncode}; stderr={r.stderr}"
        assert "nonexistent" in r.stderr


def test_check_mode_passes_when_ref_exists():
    """--check should pass when .tex ref matches an extracted snippet."""
    with tempfile.TemporaryDirectory() as td:
        repo = make_repo(Path(td))
        (repo / "src" / "lib.rs").write_text(
            "// @book-snippet:hello\n"
            "fn hello() {}\n"
            "// @book-snippet-end\n",
            encoding="utf-8",
        )
        (repo / "docs" / "libro" / "chap.tex").write_text(
            "\\inputminted{rust}{listings/hello.rs}\n",
            encoding="utf-8",
        )
        r = run_extractor(repo, repo / "out", check=True)
        assert r.returncode == 0, r.stderr


def test_skips_archive_directory():
    """Snippets inside _archive/ should be ignored."""
    with tempfile.TemporaryDirectory() as td:
        repo = make_repo(Path(td))
        archive_dir = repo / "docs" / "_archive"
        archive_dir.mkdir()
        (archive_dir / "old.rs").write_text(
            "// @book-snippet:should-skip\nfn x() {}\n// @book-snippet-end\n",
            encoding="utf-8",
        )
        r = run_extractor(repo, repo / "out")
        assert r.returncode == 0
        assert not (repo / "out" / "should-skip.rs").exists()


def test_unterminated_snippet_emits_warning():
    """A @book-snippet without matching -end should warn but not crash."""
    with tempfile.TemporaryDirectory() as td:
        repo = make_repo(Path(td))
        (repo / "src" / "bad.rs").write_text(
            "// @book-snippet:never-closed\nfn foo() {}\n",
            encoding="utf-8",
        )
        r = run_extractor(repo, repo / "out")
        assert r.returncode == 0
        assert "WARNING" in r.stderr or "never-closed" in r.stderr


if __name__ == "__main__":
    tests = [
        test_no_snippets_empty_repo,
        test_extracts_single_snippet,
        test_check_mode_passes_with_no_refs,
        test_check_mode_fails_on_missing_ref,
        test_check_mode_passes_when_ref_exists,
        test_skips_archive_directory,
        test_unterminated_snippet_emits_warning,
    ]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"  PASS: {t.__name__}")
        except AssertionError as e:
            print(f"  FAIL: {t.__name__} -- {e}")
            failures += 1
    if failures:
        print(f"\n{failures}/{len(tests)} failed")
        sys.exit(1)
    print(f"\nAll {len(tests)} tests passed")
