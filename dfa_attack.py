"""
Differential fault attack (DFA) on ARADI with random nibble faults (PNDs).

The attack recovers the equivalent round key kappa = L_j(k) column by column:
column p of kappa is the 4-bit value (kappa_w[p], kappa_x[p], kappa_y[p],
kappa_z[p]).  Each faulty/correct pair gives, at every active S-box column p
of the round following the injection, a membership constraint
      S^{-1}(c_p ^ kappa_p) ^ S^{-1}(c'_p ^ kappa_p)  in  D_p
on the 16 possible values of kappa_p.  D_p depends on what the attacker
knows about the input difference (w, x, y, z bits):

  model "paper"  : only the z bit is used (Delta z = 1)          -> 8 values
  model "full"   : Delta x = 0 and Delta z known                 -> 4 (or 3) values
  model "word"   : Delta x = 0 only (fault position unknown)     -> 7 values

Column candidates are independent, so the key space is the product of the
per-column candidate counts.  No SAT solver is needed; a 2^16 brute force
over a 16-bit "group" of the paper gives the same candidate set (checked in
verify_group_equivalence()).
"""
from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from aradi import (SBOX_INV, NUM_ROUNDS, State, encrypt, expand_key, linear_map,
                   decrypt_one_round, key_update, master_from_key_state)
from fault_model import (is_achievable, submask_images, pnd_set, pnd_sampling_space, supp,
                         window_differences, propagate_z)

WORD = 32
ALL16 = tuple(range(16))


# ---------------------------------------------------------------------------
# helpers on columns
# ---------------------------------------------------------------------------
def columns(w: int, x: int, y: int, z: int) -> List[int]:
    """4-bit column values (w<<3 | x<<2 | y<<1 | z) for p = 0..31."""
    return [(((w >> p) & 1) << 3) | (((x >> p) & 1) << 2) | (((y >> p) & 1) << 1) | ((z >> p) & 1)
            for p in range(WORD)]


def words_from_columns(cols: Sequence[int]) -> State:
    w = x = y = z = 0
    for p, v in enumerate(cols):
        w |= ((v >> 3) & 1) << p
        x |= ((v >> 2) & 1) << p
        y |= ((v >> 1) & 1) << p
        z |= (v & 1) << p
    return w, x, y, z


def lin_words(j: int, s: State) -> State:
    return tuple(linear_map(j, v) for v in s)  # type: ignore[return-value]


# allowed input-difference sets ---------------------------------------------
def allowed_set(model: str, dz: Optional[int]) -> Tuple[int, ...]:
    """Allowed S-box input differences (4-bit, w msb) at an active column."""
    if model == "paper":            # only Delta z used; requires dz == 1
        assert dz == 1
        return tuple(d for d in range(1, 16) if d & 1)
    if model == "full":             # Delta x = 0, Delta z = dz
        return tuple(d for d in range(1, 16) if ((d >> 2) & 1) == 0 and (d & 1) == dz)
    if model == "word":             # Delta x = 0 only
        return tuple(d for d in range(1, 16) if ((d >> 2) & 1) == 0)
    raise ValueError(model)


# ---------------------------------------------------------------------------
# Identification tables: activity pattern -> injected difference
# ---------------------------------------------------------------------------
class Identifier:
    """Maps the observed set of active S-box columns (bitmask) back to the
    injected difference, for a family of differences.

    A difference delta can produce the pattern A iff
        supp L(delta)  subset of  A  subset of  U(delta)
    and A = supp L(delta) | supp L(m1) | supp L(m2) for some m1, m2 subset of
    delta.  Candidates are pre-filtered with the two inclusions and then
    checked exactly.  If more than one delta can produce A the pattern is
    ambiguous and the pair is rejected."""

    def __init__(self, deltas: Sequence[int], j: int):
        self.j = j
        self.info: List[Tuple[int, int, int]] = []      # (delta, base mask, potential mask)
        for d in deltas:
            p = propagate_z(d, j)
            pot = 0
            for t in p.potential:
                pot |= 1 << t
            self.info.append((d, p.dz_word, pot))
        self._imgs: Dict[int, List[int]] = {}
        self.n_ambiguous = 0

    def identify(self, active_mask: int) -> Optional[int]:
        found = None
        for d, base, pot in self.info:
            if base & ~active_mask or active_mask & ~pot:
                continue
            if d not in self._imgs:
                self._imgs[d] = submask_images(d, self.j)
            if is_achievable(d, self.j, active_mask, self._imgs[d]):
                if found is not None:
                    self.n_ambiguous += 1
                    return None
                found = d
        return found


# ---------------------------------------------------------------------------
# Fault campaign
# ---------------------------------------------------------------------------
@dataclass
class Pair:
    c_tilde: List[int]        # columns of L_{j_next}(S^{r+1}) (correct)
    c_tilde_f: List[int]      # same for faulty
    active: frozenset         # active S-box columns of round r+1
    delta: Optional[int]      # identified injected difference (None if rejected)
    dz: Optional[int]         # known Delta z^r word (None in word model)


@dataclass
class ColumnState:
    cands: List[List[int]] = field(default_factory=lambda: [list(ALL16) for _ in range(WORD)])
    n_eq: List[int] = field(default_factory=lambda: [0] * WORD)

    def log2_keyspace(self) -> float:
        return sum(math.log2(len(c)) for c in self.cands)

    def unique(self) -> bool:
        return all(len(c) == 1 for c in self.cands)


class Attack:
    """Simulates the fault campaign on the round whose S-box follows the
    injection round, and solves for the equivalent key of that round.

    r_inj   : round at whose start the fault is injected (15 -> last-round key)
    model   : "paper", "full", "word"
    fault   : "nibble" (PND), "bit", "byte", "word"
    """

    def __init__(self, master: Sequence[int], r_inj: int, rng: random.Random,
                 model: str = "full", fault: str = "nibble", same_plaintext: bool = False):
        self.rks, self.kstates = expand_key(master)
        self.r_inj = r_inj
        self.j_inj = (r_inj - 1) % 4          # linear layer of the injection round
        self.j_next = r_inj % 4               # linear layer of the following round
        self.rng = rng
        self.model = model
        self.fault = fault
        self.same_plaintext = same_plaintext
        self.fixed_pt = tuple(rng.getrandbits(32) for _ in range(4))
        if fault == "nibble":
            self.space = pnd_sampling_space()
            self.ident = Identifier(pnd_set(), self.j_inj)
        elif fault == "nibble_aligned":          # only the 8 aligned nibbles
            self.space = [(4 * m, v) for m in range(8) for v in range(1, 16)]
            self.ident = Identifier(pnd_set(), self.j_inj)
        elif fault == "bit":
            self.space = None
            self.ident = Identifier(window_differences(1), self.j_inj)
        elif fault == "byte":
            self.space = [(k, v) for k in range(WORD - 8 + 1) for v in range(1, 256)]
            self.ident = Identifier(window_differences(8), self.j_inj)
        elif fault == "word":
            self.space = None
            self.ident = None
        else:
            raise ValueError(fault)
        # true equivalent key of round r_inj+1
        self.kappa_true = columns(*lin_words(self.j_next, self.rks[r_inj + 1]))
        self.n_injected = 0
        self.n_rejected = 0

    # -- one injection -------------------------------------------------------
    def sample_delta(self) -> int:
        if self.fault in ("nibble", "nibble_aligned", "byte"):
            k, v = self.rng.choice(self.space)
            return v << k
        if self.fault == "bit":
            return 1 << self.rng.randrange(WORD)
        return self.rng.randrange(1, 1 << WORD)          # random non-zero word

    def inject(self, delta: Optional[int] = None) -> Pair:
        """Encrypt one plaintext twice (correct / faulty), peel the rounds above
        r_inj+1 with the already recovered round keys and return the data the
        attacker works with.  Peeling uses the true later round keys; the
        multi-candidate case is handled in master_key_recovery.py."""
        self.n_injected += 1
        if delta is None:
            delta = self.sample_delta()
        pt = self.fixed_pt if self.same_plaintext else tuple(self.rng.getrandbits(32) for _ in range(4))
        c = encrypt(pt, self.rks)
        cf = encrypt(pt, self.rks, fault=(self.r_inj, 3, delta))
        return self.pair_from_ciphertexts(c, cf, self.rks)

    def pair_from_ciphertexts(self, c: State, cf: State, rks_known: Sequence[State]) -> Pair:
        """Attacker side: peel rounds 16..r_inj+2, form columns, identify the fault."""
        s, sf = c, cf
        for r in range(NUM_ROUNDS, self.r_inj + 1, -1):
            s = decrypt_one_round(s, rks_known[r], r)
            sf = decrypt_one_round(sf, rks_known[r], r)
        # S-box output of round r_inj+1 = L_{j_next}(S^{r_inj+1}) ^ kappa
        ct = columns(*lin_words(self.j_next, s))
        ctf = columns(*lin_words(self.j_next, sf))
        active = frozenset(p for p in range(WORD) if ct[p] != ctf[p])
        if self.fault == "word":
            return Pair(ct, ctf, active, None, None)
        active_mask = 0
        for p in active:
            active_mask |= 1 << p
        d = self.ident.identify(active_mask)
        if d is None:
            self.n_rejected += 1
            return Pair(ct, ctf, active, None, None)
        return Pair(ct, ctf, active, d, linear_map(self.j_inj, d))

    # -- constraints ---------------------------------------------------------
    def constraints(self, pair: Pair) -> List[Tuple[int, Tuple[int, ...]]]:
        """List of (column, allowed input differences) for one pair."""
        out = []
        if self.fault == "word":
            allowed = allowed_set("word", None)
            return [(p, allowed) for p in pair.active]
        if pair.delta is None:
            return out
        for p in pair.active:
            dz = (pair.dz >> p) & 1
            if self.model == "paper":
                if dz == 1:
                    out.append((p, allowed_set("paper", 1)))
            else:
                out.append((p, allowed_set("full", dz)))
        return out

    @staticmethod
    def filter_column(cands: List[int], ct: int, ctf: int, allowed: Tuple[int, ...]) -> List[int]:
        return [k for k in cands if (SBOX_INV[ct ^ k] ^ SBOX_INV[ctf ^ k]) in allowed]

    def apply(self, state: ColumnState, pair: Pair) -> None:
        for p, allowed in self.constraints(pair):
            state.cands[p] = self.filter_column(state.cands[p], pair.c_tilde[p], pair.c_tilde_f[p], allowed)
            state.n_eq[p] += 1
            assert self.kappa_true[p] in state.cands[p], "true key eliminated: bug or wrong fault model"

    def recovered_round_key(self, state: ColumnState) -> State:
        assert state.unique()
        kappa = words_from_columns([c[0] for c in state.cands])
        return lin_words(self.j_next, kappa)  # k = L_j(kappa), involution

    # -- a whole campaign ----------------------------------------------------
    def run_until_unique(self, max_faults: int = 1000) -> Tuple[int, ColumnState, List[float]]:
        """Inject until every column is unique.  Returns (#injections, state,
        log2 keyspace after each injection)."""
        state = ColumnState()
        curve = []
        n = 0
        while not state.unique() and n < max_faults:
            pair = self.inject()
            self.apply(state, pair)
            n += 1
            curve.append(state.log2_keyspace())
        return n, state, curve


# ---------------------------------------------------------------------------
# Paper's 16-bit groups (round 16): check per-column decomposition == group brute force
# ---------------------------------------------------------------------------
GROUP_COLUMNS = [[0, 8, 23, 31], [1, 9, 16, 24], [2, 10, 17, 25], [3, 11, 18, 26],
                 [4, 12, 19, 27], [5, 13, 20, 28], [6, 14, 21, 29], [7, 15, 22, 30]]


def verify_group_equivalence(seed: int = 1, n_faults: int = 12) -> bool:
    """Brute force the 16 real key bits k^16_{w,x,y,z}[positions of group g]
    against all paper-model equations of the group and compare with the
    product of the per-column candidate sets of kappa."""
    rng = random.Random(seed)
    master = [rng.getrandbits(32) for _ in range(8)]
    atk = Attack(master, 15, rng, model="paper")
    state = ColumnState()
    pairs = [atk.inject() for _ in range(n_faults)]
    for pr in pairs:
        atk.apply(state, pr)
    k16 = atk.rks[16]
    ok = True
    for g, cols in enumerate(GROUP_COLUMNS):
        # candidates from the column decomposition, mapped back to the 16 real key bits
        col_prod = set()
        for combo in itertools_product([state.cands[p] for p in cols]):
            kappa_cols = [0] * WORD
            for p, v in zip(cols, combo):
                kappa_cols[p] = v
            kw = lin_words(3, words_from_columns(kappa_cols))
            col_prod.add(tuple(((kw[a] >> p) & 1) for a in range(4) for p in cols))
        # brute force over the 16 real bits of the group
        bf = set()
        for guess in range(1 << 16):
            kw = [0, 0, 0, 0]
            bitpos = 0
            for a in range(4):
                for p in cols:
                    kw[a] |= ((guess >> bitpos) & 1) << p
                    bitpos += 1
            kappa = columns(*lin_words(3, tuple(kw)))
            good = True
            for pr in pairs:
                for p, allowed in atk.constraints(pr):
                    if p in cols and (SBOX_INV[pr.c_tilde[p] ^ kappa[p]] ^ SBOX_INV[pr.c_tilde_f[p] ^ kappa[p]]) not in allowed:
                        good = False
                        break
                if not good:
                    break
            if good:
                bf.add(tuple(((kw[a] >> p) & 1) for a in range(4) for p in cols))
        truth = tuple(((k16[a] >> p) & 1) for a in range(4) for p in cols)
        ok &= (bf == col_prod) and (truth in bf)
        print(f"group {g+1}: columns {cols}, equations {sum(state.n_eq[p] for p in cols)}, "
              f"brute-force candidates {len(bf)}, column-product candidates {len(col_prod)}, equal={bf == col_prod}")
    return ok


def itertools_product(lists):
    import itertools
    return itertools.product(*lists)


if __name__ == "__main__":
    print("per-column decomposition vs 2^16 brute force on the paper's groups:")
    print("all equal:", verify_group_equivalence())
