"""
Fault-model analysis for the DFA on ARADI.

* D_b^Delta : the set of permissible nibble differences (PNDs) of a b-bit word.
* Propagation of a difference injected into word z at the start of round r
  through the S-box layer and the linear layer L_j of round r.
* Collision analysis: can two different PNDs produce the same observable
  pattern of active S-box columns in round r+1 ?
* Comparison of bit / nibble / byte / word fault models.

Conventions follow aradi.py.  A "column" p (0 <= p < 32) is the 4-bit S-box
input (w[p], x[p], y[p], z[p]).
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Sequence, Set, Tuple

from aradi import linear_map, MASK32

WORD = 32


def supp(v: int) -> Tuple[int, ...]:
    """Sorted tuple of set-bit indices of v."""
    return tuple(i for i in range(WORD) if (v >> i) & 1)


def hw(v: int) -> int:
    return bin(v).count("1")


def window_differences(width: int, b: int = WORD) -> List[int]:
    """All non-zero b-bit values whose set bits fit in some window of `width`
    consecutive bit positions (each value listed once).  width=1: bit faults,
    width=4: PNDs, width=8: byte-window faults."""
    out: Set[int] = set()
    for k in range(b - width + 1):          # window occupies bits k .. k+width-1
        for v in range(1, 1 << width):
            out.add(v << k)
    return sorted(out)


def pnd_set(b: int = WORD) -> List[int]:
    return window_differences(4, b)


def pnd_sampling_space(b: int = WORD) -> List[Tuple[int, int]]:
    """The (window, value) pairs the random nibble-fault model samples uniformly:
    29 windows x 15 non-zero nibble values = 435 pairs (not all distinct as
    32-bit differences)."""
    return [(k, v) for k in range(b - 4 + 1) for v in range(1, 16)]


# ---------------------------------------------------------------------------
# Propagation of a z-word difference through one round
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Propagation:
    delta: int                      # injected difference in word z (start of round r)
    j: int                          # linear layer index of round r
    certain: Tuple[int, ...]        # supp(L_j(delta)) : columns with Delta z^{r} = 1 for sure
    potential: Tuple[int, ...]      # union of supp(L_j(e_t)), t in supp(delta): columns that may be active
    dz_word: int                    # L_j(delta) as a 32-bit word

    @property
    def cancellation_free(self) -> bool:
        return len(self.certain) == 3 * hw(self.delta)


def propagate_z(delta: int, j: int) -> Propagation:
    """Difference `delta` in word z at the start of a round whose linear layer
    is L_j.  After the S-box: Delta z* = delta (certain), Delta x* = 0 (certain),
    Delta y* = w & delta, Delta w* = x* & delta (data dependent).  After L_j the
    known part is Delta z = L_j(delta)."""
    dz = linear_map(j, delta)
    pot: Set[int] = set()
    for t in supp(delta):
        pot.update(supp(linear_map(j, 1 << t)))
    return Propagation(delta, j, supp(dz), tuple(sorted(pot)), dz)


def submask_images(delta: int, j: int) -> List[int]:
    """{L_j(m) : m subset of delta} as 32-bit masks (one per sub-mask m)."""
    bits = supp(delta)
    out = []
    for m in range(1 << len(bits)):
        d = sum(1 << bits[i] for i in range(len(bits)) if (m >> i) & 1)
        out.append(linear_map(j, d))
    return out


def achievable_active_masks(delta: int, j: int) -> Set[int]:
    """All column-activity patterns (as 32-bit masks) at the next S-box layer
    that the injected difference `delta` can produce, over all values of the
    data-dependent bits (w & delta) and (x* & delta):
        A = supp L(delta) | supp L(w & delta) | supp L(x* & delta)."""
    base = linear_map(j, delta)
    imgs = submask_images(delta, j)
    return {base | s1 | s2 for s1 in imgs for s2 in imgs}


def is_achievable(delta: int, j: int, pattern: int, imgs: Sequence[int] | None = None) -> bool:
    """Can `delta` produce activity pattern `pattern` (bitmask)?"""
    base = linear_map(j, delta)
    if base & ~pattern:
        return False
    if imgs is None:
        imgs = submask_images(delta, j)
    sub = [s for s in imgs if not (s & ~pattern)]
    for s1 in sub:
        need = pattern & ~(base | s1)
        for s2 in sub:
            if (s2 & need) == need:
                return True
    return False


def achievable_active_sets(delta: int, j: int) -> Set[FrozenSet[int]]:
    """Same as achievable_active_masks but as frozensets of column indices."""
    return {frozenset(supp(m)) for m in achievable_active_masks(delta, j)}


def collision_report(deltas: Sequence[int], j: int) -> Dict:
    """For a family of differences, report (i) how many are cancellation free,
    (ii) whether the map delta -> certain pattern is injective, (iii) whether
    any two distinct deltas share an achievable activity pattern."""
    props = [propagate_z(d, j) for d in deltas]
    n_cf = sum(p.cancellation_free for p in props)
    certain_map: Dict[Tuple[int, ...], List[int]] = {}
    for p in props:
        certain_map.setdefault(p.certain, []).append(p.delta)
    certain_collisions = {k: v for k, v in certain_map.items() if len(v) > 1}
    pattern_owner: Dict[FrozenSet[int], Set[int]] = {}
    for d in deltas:
        for pat in achievable_active_sets(d, j):
            pattern_owner.setdefault(pat, set()).add(d)
    ambiguous_patterns = {k: v for k, v in pattern_owner.items() if len(v) > 1}
    ambiguous_deltas = set()
    for v in ambiguous_patterns.values():
        ambiguous_deltas |= v
    return {
        "j": j,
        "n_deltas": len(deltas),
        "n_cancellation_free": n_cf,
        "n_with_cancellation": len(deltas) - n_cf,
        "certain_pattern_injective": len(certain_collisions) == 0,
        "n_certain_pattern_collisions": len(certain_collisions),
        "n_ambiguous_activity_patterns": len(ambiguous_patterns),
        "n_deltas_in_ambiguous_patterns": len(ambiguous_deltas),
        "deltas_with_cancellation": [p.delta for p in props if not p.cancellation_free],
        "ambiguous_patterns": {tuple(sorted(k)): sorted(v) for k, v in ambiguous_patterns.items()},
    }


# ---------------------------------------------------------------------------
# Two-round propagation for the tables of the paper
# ---------------------------------------------------------------------------
def end_of_round_r_plus_1(active_cols: Iterable[int], j_next: int) -> Tuple[int, ...]:
    """Union of supp(L_{j_next}(e_p)) over active columns p: bit positions of
    every word that can be active at the end of round r+1."""
    out: Set[int] = set()
    for p in active_cols:
        out.update(supp(linear_map(j_next, 1 << p)))
    return tuple(sorted(out))


def bit_table(j_inject: int = 2, j_next: int = 3) -> List[Tuple[int, Tuple[int, ...], Tuple[int, ...]]]:
    rows = []
    for i in range(WORD):
        p = propagate_z(1 << i, j_inject)
        rows.append((i, p.certain, end_of_round_r_plus_1(p.certain, j_next)))
    return rows


def nibble_table(j_inject: int = 2, j_next: int = 3) -> List[Tuple[int, Tuple[int, ...], Tuple[int, ...]]]:
    rows = []
    for k in range(WORD - 4 + 1):
        d = 0xF << k
        p = propagate_z(d, j_inject)
        rows.append((d, p.certain, end_of_round_r_plus_1(p.potential, j_next)))
    return rows


# ---------------------------------------------------------------------------
# Equation probabilities (boundary effect of the sliding nibble window)
# ---------------------------------------------------------------------------
def equation_probability_theory(j: int = 2, b: int = WORD) -> List[float]:
    """P[column p gets a known active difference] for one random PND sampled as
    (uniform window k in 0..b-4, uniform non-zero nibble value).  Exact closed
    form: a bit t of the word is flipped with probability
    n(t)/(b-3) * 8/15, where n(t) = number of windows containing t.  Because
    L_j is cancellation free on PNDs (checked separately) and the three
    preimage bits of a column are never inside one window, the events are
    disjoint and the probabilities add."""
    n_win = b - 4 + 1
    def n_windows(t: int) -> int:
        return sum(1 for k in range(n_win) if k <= t <= k + 3)
    probs = []
    for p in range(b):
        pre = [t for t in range(b) if (linear_map(j, 1 << t) >> p) & 1]
        assert len(pre) == 3
        # the three preimage bits must be pairwise more than 3 apart for disjointness
        for t1, t2 in itertools.combinations(pre, 2):
            assert abs(t1 - t2) > 3, (p, pre)
        probs.append(sum(n_windows(t) for t in pre) / n_win * (8 / 15))
    return probs


if __name__ == "__main__":
    import json
    print("|D_32| (distinct PNDs) =", len(pnd_set()), "; sampling pairs =", len(pnd_sampling_space()))
    for j in range(4):
        rep = collision_report(pnd_set(), j)
        print(f"L_{j}: cancellation-free {rep['n_cancellation_free']}/{rep['n_deltas']}, "
              f"certain-pattern injective: {rep['certain_pattern_injective']}, "
              f"ambiguous activity patterns: {rep['n_ambiguous_activity_patterns']}, "
              f"PNDs involved: {rep['n_deltas_in_ambiguous_patterns']}")
        if rep["deltas_with_cancellation"]:
            print("   with cancellation:", [hex(d) for d in rep["deltas_with_cancellation"]])
    print()
    for width in (1, 2, 3, 4, 5, 6, 7, 8):
        rep = collision_report(window_differences(width), 2)
        print(f"window {width}: {rep['n_deltas']} differences, cancellation-free {rep['n_cancellation_free']}, "
              f"certain injective {rep['certain_pattern_injective']}, ambiguous patterns {rep['n_ambiguous_activity_patterns']}, "
              f"deltas involved {rep['n_deltas_in_ambiguous_patterns']}")
    print()
    pr = equation_probability_theory(2)
    print("equation probability per z^15 column (theory):")
    print(" ".join(f"{p:.3f}" for p in pr))
