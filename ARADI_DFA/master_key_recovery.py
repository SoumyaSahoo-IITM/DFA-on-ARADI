"""
End-to-end master-key recovery for ARADI by three fault campaigns:

  campaign 1: PNDs into z at the start of round 15  -> kappa16 = L_3(k_16)
  campaign 2: PNDs into z at the start of round 14  -> kappa15 = L_2(k_15)
  campaign 3: PNDs into z at the start of round 13  -> kappa14 = L_1(k_14)

The state at the end of round 15 (resp. 14) is obtained by partially
decrypting the correct and faulty ciphertexts with the recovered k_16 (resp.
k_16, k_15).  When a campaign leaves more than one candidate per column, all
full candidates are enumerated and eliminated by the next campaign:
  * a wrong k_16 makes the round-15 activity pattern of (almost) every
    campaign-2 pair match no PND, or leaves no consistent kappa15 value;
  * the key schedule gives a 64-bit check between k_15 and k_16
    (k_15 determines K^16_1 and K^16_3 = words x and z of k_16) and a second
    64-bit check between k_14 and k_16 (K^16_0 and K^16_2).
The master key K^0 is finally obtained by inverting the key schedule from
K^16 = (K^16_0..7) and verified on one plaintext/ciphertext pair.
"""
from __future__ import annotations

import itertools
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from aradi import (NUM_ROUNDS, State, encrypt, expand_key, key_update, m0, m1,
                   master_from_key_state)
from dfa_attack import Attack, ColumnState, lin_words, words_from_columns, WORD


def k16_from_k15_k14(k15: State, k14: State) -> List[int]:
    """Key-schedule relations (steps 14 and 15):
       k_14 = K^14_0..3 -> K^15_0..3 -> K^16_0, K^16_4, K^16_2, K^16_6
       k_15 = K^15_4..7 -> K^16_1, K^16_5, K^16_3, K^16_7
    Returns the full key state K^16 implied by (k_15, k_14)."""
    # step 14 (even): M0(K0,K1), M1(K2,K3) then swap 1<->2 ; words 0..3 of K^15
    a0, a1 = m0(k14[0], k14[1])
    b0, b1 = m1(k14[2], k14[3])
    K15_0, K15_1, K15_2, K15_3 = a0, b0, a1, b1
    # step 15 (odd): M0(K0,K1)->(K16_0, new1), M1(K2,K3)->(K16_2, new3),
    #                M0(K4,K5)->(new4, K16_5), M1(K6,K7)->(new6, K16_7 ^ 15)
    #                then swap 1<->4, 3<->6
    c0, c1 = m0(K15_0, K15_1)
    d0, d1 = m1(K15_2, K15_3)
    e0, e1 = m0(k15[0], k15[1])     # K^15_4, K^15_5
    f0, f1 = m1(k15[2], k15[3])     # K^15_6, K^15_7
    K16 = [c0, e0, d0, f0, c1, e1, d1, f1 ^ 15]
    return K16


@dataclass
class CampaignData:
    r_inj: int
    cts: List[Tuple[State, State]] = field(default_factory=list)   # (correct, faulty)


class MasterKeyAttack:
    def __init__(self, master: Sequence[int], rng: random.Random, model: str = "full",
                 fault: str = "nibble"):
        self.master = list(master)
        self.rks, self.kstates = expand_key(master)
        self.rng = rng
        self.model = model
        self.fault = fault
        # one Attack object per injection round (gives us identifiers and constraints)
        self.atk = {r: Attack(master, r, rng, model=model, fault=fault) for r in (15, 14, 13)}
        self.stats: Dict[str, float] = {}

    # -- fault campaigns (device side) -------------------------------------
    def collect(self, r_inj: int, n: int) -> CampaignData:
        data = CampaignData(r_inj)
        atk = self.atk[r_inj]
        for _ in range(n):
            delta = atk.sample_delta()
            pt = tuple(self.rng.getrandbits(32) for _ in range(4))
            c = encrypt(pt, self.rks)
            cf = encrypt(pt, self.rks, fault=(r_inj, 3, delta))
            data.cts.append((c, cf))
        return data

    # -- attacker side -----------------------------------------------------
    def solve_round(self, data: CampaignData, known_rks: Dict[int, State],
                    early_abort: bool = False) -> Optional[ColumnState]:
        """Filter the equivalent key of round r_inj+1 with all pairs of the
        campaign, peeling the later rounds with known_rks.  Returns None if a
        pair is rejected by the identifier or a column runs empty (only
        possible when a wrong later-round key was used)."""
        atk = self.atk[data.r_inj]
        rks = list(self.rks)                      # only the entries in known_rks are read
        for r, k in known_rks.items():
            rks[r] = k
        st = ColumnState()
        self.pairs_examined = 0
        for c, cf in data.cts:
            self.pairs_examined += 1
            pair = atk.pair_from_ciphertexts(c, cf, rks)
            if pair.delta is None and self.fault != "word":
                if early_abort:
                    return None
                continue
            for p, allowed in atk.constraints(pair):
                st.cands[p] = Attack.filter_column(st.cands[p], pair.c_tilde[p], pair.c_tilde_f[p], allowed)
                st.n_eq[p] += 1
                if not st.cands[p]:
                    return None
        return st

    @staticmethod
    def enumerate_keys(st: ColumnState, j: int):
        for combo in itertools.product(*st.cands):
            yield lin_words(j, words_from_columns(combo))

    def run(self, n1: int, n2: int, n3: int, max_enum: int = 1 << 20) -> Dict:
        t0 = time.perf_counter()
        d1 = self.collect(15, n1)
        d2 = self.collect(14, n2)
        d3 = self.collect(13, n3)
        t_collect = time.perf_counter() - t0

        t1 = time.perf_counter()
        st16 = self.solve_round(d1, {})
        assert st16 is not None
        n16 = 2 ** st16.log2_keyspace()
        if n16 > max_enum:
            return {"ok": False, "reason": f"too many k16 candidates: 2^{st16.log2_keyspace():.1f}",
                    "log2_k16": st16.log2_keyspace()}
        tested16 = 0
        pairs_to_reject = []    # campaign-2 pairs examined before a wrong k16 is rejected
        survivors = []          # (k16, k15 state)
        for k16 in self.enumerate_keys(st16, 3):
            tested16 += 1
            st15 = self.solve_round(d2, {16: k16}, early_abort=True)
            if st15 is None:
                pairs_to_reject.append(self.pairs_examined)
                continue
            n15 = 2 ** st15.log2_keyspace()
            if n15 > max_enum:
                return {"ok": False, "reason": "too many k15 candidates", "log2_k15": st15.log2_keyspace()}
            for k15 in self.enumerate_keys(st15, 2):
                # 64-bit key-schedule check: k_15 -> K^16_1, K^16_3 = words x, z of k_16
                e0, _ = m0(k15[0], k15[1])
                f0, _ = m1(k15[2], k15[3])
                if e0 != k16[1] or f0 != k16[3]:
                    continue
                survivors.append((k16, k15, st15))
        results = []
        tested15 = len(survivors)
        for k16, k15, st15 in survivors:
            st14 = self.solve_round(d3, {16: k16, 15: k15}, early_abort=True)
            if st14 is None:
                continue
            for k14 in self.enumerate_keys(st14, 1):
                K16 = k16_from_k15_k14(k15, k14)
                if K16[0] != k16[0] or K16[2] != k16[2]:
                    continue
                master = master_from_key_state(K16, 16)
                # final check on one plaintext/ciphertext pair
                pt = (0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210)
                rks, _ = expand_key(master)
                if encrypt(pt, rks) == encrypt(pt, self.rks):
                    results.append(master)
        t_solve = time.perf_counter() - t1
        ok = len(results) == 1 and results[0] == self.master
        return {
            "ok": ok, "n_master_candidates": len(results),
            "log2_k16": st16.log2_keyspace(), "k16_candidates_tested": tested16,
            "k16_k15_survivors_after_schedule_check": tested15,
            "faults": n1 + n2 + n3, "t_collect_s": t_collect, "t_solve_s": t_solve,
            "mean_pairs_to_reject_wrong_k16": (sum(pairs_to_reject) / len(pairs_to_reject)) if pairs_to_reject else None,
            "max_pairs_to_reject_wrong_k16": max(pairs_to_reject) if pairs_to_reject else None,
        }


if __name__ == "__main__":
    import sys
    rng = random.Random(42)
    for trial in range(3):
        master = [rng.getrandbits(32) for _ in range(8)]
        mk = MasterKeyAttack(master, rng, model="full")
        res = mk.run(36, 36, 36)
        print(res)
