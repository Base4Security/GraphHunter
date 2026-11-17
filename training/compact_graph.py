"""A memory-bounded stand-in for the slice of NetworkX this pipeline uses.

`02_extract_subgraphs.py` was written against `nx.DiGraph` when the corpus
was assumed to hold ~2.3M edges. The real CADETS corpus holds **34.7M**,
and NetworkX spends roughly a kilobyte per edge on dict-of-dicts
bookkeeping — tens of gigabytes, on a 14 GiB machine.

The script only ever asks ten questions of the graph, all of them
neighbourhood lookups for a bounded k-hop BFS. That is a CSR adjacency,
not a general graph library:

    nodes()            successors(n)     out_degree(n)
    has_node(n)        predecessors(n)   in_degree(n)
    number_of_nodes()  get_edge_data(u,v)
    number_of_edges()  add_edge(u, v, rel_type)

Storage, for 2.85M nodes and 34.7M edges:

    id -> index dict   ~250 MB   (the unavoidable cost: UUID strings)
    forward CSR        ~170 MB   (int32 targets + int32 offsets)
    reverse CSR        ~170 MB
    relation type      ~35 MB    (one uint8 per edge)

...around 600 MB, versus tens of GB. Building it costs one pass to collect
edges and one to lay out the CSR, both linear.
"""

from __future__ import annotations

from array import array
from typing import Iterable, Iterator


class CompactGraph:
    """Directed multigraph over interned string ids, backed by CSR arrays."""

    def __init__(self) -> None:
        self._idx: dict[str, int] = {}
        self._ids: list[str] = []
        # Edge list, accumulated during load. Released once CSR is built.
        self._src: array | None = array("i")
        self._dst: array | None = array("i")
        self._rel: array | None = array("B")
        self._rel_names: list[str] = []
        self._rel_idx: dict[str, int] = {}
        # CSR, built by `finalize`.
        self._fwd_off: array | None = None
        self._fwd_tgt: array | None = None
        self._fwd_rel: array | None = None
        self._bwd_off: array | None = None
        self._bwd_tgt: array | None = None
        self._n_edges = 0

    # ---- construction ---------------------------------------------------

    def _index_of(self, uid: str) -> int:
        i = self._idx.get(uid)
        if i is None:
            i = len(self._ids)
            self._idx[uid] = i
            self._ids.append(uid)
        return i

    def add_node(self, uid: str) -> None:
        self._index_of(uid)

    def add_edge(self, src: str, dst: str, rel_type: str = "Connect") -> None:
        """Mirrors `nx.DiGraph.add_edge`, including implicit node creation."""
        assert self._src is not None, "add_edge after finalize()"
        r = self._rel_idx.get(rel_type)
        if r is None:
            r = len(self._rel_names)
            self._rel_idx[rel_type] = r
            self._rel_names.append(rel_type)
        self._src.append(self._index_of(src))
        self._dst.append(self._index_of(dst))
        self._rel.append(min(r, 255))

    def finalize(self) -> None:
        """Lays the edge list out as forward and reverse CSR."""
        assert self._src is not None
        n = len(self._ids)
        m = len(self._src)
        self._n_edges = m

        def build(src: array, dst: array, carry_rel: bool):
            counts = array("i", bytes(4 * (n + 1)))
            for s in src:
                counts[s + 1] += 1
            for i in range(1, n + 1):
                counts[i] += counts[i - 1]
            offsets = counts
            targets = array("i", bytes(4 * m))
            rels = array("B", bytes(m)) if carry_rel else None
            cursor = array("i", offsets[:n])
            for e in range(m):
                s = src[e]
                pos = cursor[s]
                targets[pos] = dst[e]
                if rels is not None:
                    rels[pos] = self._rel[e]
                cursor[s] = pos + 1

            # Collapse parallel edges, matching `nx.DiGraph`.
            #
            # This is a semantic choice, not a detail: an entity that reads
            # the same file 500 times has 500 events, and keeping them
            # would inflate its degree 500-fold. Degree is a model FEATURE
            # (gnn_bridge.rs feeds normalized in/out degree into the input
            # tensor), so training on multigraph degrees while inference
            # computes something else would silently mistrain the model.
            # The pipeline was built against DiGraph; stay faithful to it.
            out_off = array("i", bytes(4 * (n + 1)))
            out_tgt = array("i", bytes(4 * m))
            out_rel = array("B", bytes(m)) if rels is not None else None
            w = 0
            for v in range(n):
                lo, hi = offsets[v], offsets[v + 1]
                out_off[v] = w
                if hi > lo:
                    order = sorted(range(lo, hi), key=lambda k: targets[k])
                    prev = -1
                    for k in order:
                        t = targets[k]
                        if t == prev:
                            continue
                        prev = t
                        out_tgt[w] = t
                        if out_rel is not None:
                            out_rel[w] = rels[k]
                        w += 1
            out_off[n] = w
            del out_tgt[w:]
            if out_rel is not None:
                del out_rel[w:]
            return out_off, out_tgt, out_rel

        self._fwd_off, self._fwd_tgt, self._fwd_rel = build(self._src, self._dst, True)
        self._bwd_off, self._bwd_tgt, _ = build(self._dst, self._src, False)
        # Post-collapse count, so this agrees with what nx.DiGraph reports.
        self._n_edges = len(self._fwd_tgt)
        # Release the edge list; the CSR is the only copy from here.
        self._src = self._dst = self._rel = None

    # ---- the NetworkX-shaped surface ------------------------------------

    def nodes(self) -> Iterator[str]:
        return iter(self._ids)

    def has_node(self, uid: str) -> bool:
        return uid in self._idx

    def number_of_nodes(self) -> int:
        return len(self._ids)

    def number_of_edges(self) -> int:
        return self._n_edges

    def _neighbours(self, uid: str, off: array, tgt: array) -> Iterable[str]:
        i = self._idx.get(uid)
        if i is None:
            return ()
        ids = self._ids
        return (ids[tgt[k]] for k in range(off[i], off[i + 1]))

    def successors(self, uid: str) -> Iterable[str]:
        return self._neighbours(uid, self._fwd_off, self._fwd_tgt)

    def predecessors(self, uid: str) -> Iterable[str]:
        return self._neighbours(uid, self._bwd_off, self._bwd_tgt)

    def out_degree(self, uid: str) -> int:
        i = self._idx.get(uid)
        return 0 if i is None else self._fwd_off[i + 1] - self._fwd_off[i]

    def in_degree(self, uid: str) -> int:
        i = self._idx.get(uid)
        return 0 if i is None else self._bwd_off[i + 1] - self._bwd_off[i]

    def get_edge_data(self, u: str, v: str, default=None):
        """Returns `{"rel_type": ...}` for the first u->v edge, like the
        dict NetworkX hands back for a simple digraph."""
        i = self._idx.get(u)
        j = self._idx.get(v)
        if i is None or j is None:
            return default
        for k in range(self._fwd_off[i], self._fwd_off[i + 1]):
            if self._fwd_tgt[k] == j:
                return {"rel_type": self._rel_names[self._fwd_rel[k]]}
        return default
