"""
Reproducible experiments for the paper.  Every trial uses its own seed
(base_seed + trial index), so results do not depend on the number of worker
processes.  Results are written as JSON into results/.

    python3 run_experiments.py all --trials 10000 --workers 8
    python3 run_experiments.py faults_to_unique --trials 2000
"""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import random
import statistics
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from typing import Dict, List

from aradi import expand_key, encrypt
from dfa_attack import Attack, ColumnState, GROUP_COLUMNS
from fault_model import (collision_report, equation_probability_theory, pnd_set,
                         window_differences)
from master_key_recovery import MasterKeyAttack

RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
MAX_FAULTS = 400


def percentiles(xs: List[float], ps=(50, 90, 95, 99)) -> Dict[str, float]:
    s = sorted(xs)
    out = {"mean": statistics.mean(s), "min": s[0], "max": s[-1], "n": len(s)}
    for p in ps:
        idx = min(len(s) - 1, math.ceil(p / 100 * len(s)) - 1)
        out[f"p{p}"] = s[idx]
    out["stdev"] = statistics.pstdev(s)
    return out


def machine_info() -> Dict:
    cpu = platform.processor() or ""
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    cpu = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    return {"python": sys.version.split()[0], "platform": platform.platform(),
            "cpu": cpu, "cpu_count": os.cpu_count()}


# ---------------------------------------------------------------------------
# E1: one campaign on round 15; record keyspace curve and #faults to unique
# ---------------------------------------------------------------------------
def _trial_curve(args):
    seed, model, fault, r_inj, n_record = args
    rng = random.Random(seed)
    master = [rng.getrandbits(32) for _ in range(8)]
    atk = Attack(master, r_inj, rng, model=model, fault=fault)
    st = ColumnState()
    curve = []
    first_unique = None
    group_log = []     # (after n faults) per-group (#equations, log2 candidates)
    n = 0
    while n < MAX_FAULTS and (first_unique is None or n < n_record):
        atk.apply(st, atk.inject())
        n += 1
        if n <= n_record:
            curve.append(round(st.log2_keyspace(), 4))
            if n in (12, 24, 36, 48, 60):
                group_log.append([n, [[sum(st.n_eq[p] for p in g),
                                       round(sum(math.log2(len(st.cands[p])) for p in g), 4)]
                                      for g in GROUP_COLUMNS]])
        if first_unique is None and st.unique():
            first_unique = n
            n_eq_at_unique = list(st.n_eq)
    if first_unique is None:
        n_eq_at_unique = list(st.n_eq)
    return {"seed": seed, "first_unique": first_unique, "curve": curve,
            "n_eq_at_unique": n_eq_at_unique, "group_log": group_log,
            "n_rejected": atk.n_rejected, "n_injected": atk.n_injected}


def exp_faults_to_unique(trials: int, seed: int, workers: int, configs=None, n_record: int = 120) -> Dict:
    if configs is None:
        configs = [("paper", "nibble", 15), ("full", "nibble", 15), ("full", "nibble_aligned", 15),
                   ("full", "bit", 15), ("full", "byte", 15), ("word", "word", 15),
                   ("full", "nibble", 14), ("full", "nibble", 13),
                   ("paper", "nibble", 14), ("paper", "nibble", 13)]
    out = {"trials": trials, "seed": seed, "n_record": n_record, "configs": {}}
    with ProcessPoolExecutor(max_workers=workers) as ex:
        for model, fault, r_inj in configs:
            t0 = time.perf_counter()
            key = f"{model}_{fault}_r{r_inj}"
            res = list(ex.map(_trial_curve, [(seed + i, model, fault, r_inj, n_record) for i in range(trials)],
                              chunksize=max(1, trials // (8 * workers))))
            fu = [r["first_unique"] for r in res if r["first_unique"] is not None]
            n_fail = sum(r["first_unique"] is None for r in res)
            # mean / percentile curves of log2 keyspace
            L = min(len(r["curve"]) for r in res)
            curves = [r["curve"][:L] for r in res]
            mean_curve = [statistics.mean(c[i] for c in curves) for i in range(L)]
            max_curve = [max(c[i] for c in curves) for i in range(L)]
            p95_curve = [sorted(c[i] for c in curves)[min(L and len(curves) - 1, math.ceil(0.95 * len(curves)) - 1)] for i in range(L)]
            frac_unique = [statistics.mean(1.0 if c[i] == 0 else 0.0 for c in curves) for i in range(L)]
            # per-column equation counts after n_record faults (from curve runs we only
            # know counts at unique; recompute separately in exp_equation_probability)
            glog: Dict[int, List[List[float]]] = {}
            for r in res:
                for n, groups in r["group_log"]:
                    glog.setdefault(n, []).append(groups)
            group_summary = {}
            for n, lst in glog.items():
                group_summary[n] = [{"mean_eq": statistics.mean(x[g][0] for x in lst),
                                     "mean_log2_cands": statistics.mean(x[g][1] for x in lst),
                                     "max_log2_cands": max(x[g][1] for x in lst)} for g in range(8)]
            out["configs"][key] = {
                "model": model, "fault": fault, "r_inj": r_inj,
                "faults_to_unique": percentiles(fu) if fu else None,
                "n_not_unique_within_max": n_fail, "max_faults": MAX_FAULTS,
                "mean_log2_keyspace": mean_curve, "p95_log2_keyspace": p95_curve,
                "max_log2_keyspace": max_curve, "frac_unique": frac_unique,
                "group_summary": group_summary,
                "n_rejected_total": sum(r["n_rejected"] for r in res),
                "n_injected_total": sum(r["n_injected"] for r in res),
                "seconds": time.perf_counter() - t0,
            }
            print(f"[E1] {key}: faults to unique {out['configs'][key]['faults_to_unique']} "
                  f"({out['configs'][key]['seconds']:.1f}s)", flush=True)
    return out


# ---------------------------------------------------------------------------
# E2: equations-vs-candidates relation per 16-bit group (paper's 27/36/45 claim)
# ---------------------------------------------------------------------------
def _trial_group_relation(args):
    seed, model = args
    rng = random.Random(seed)
    master = [rng.getrandbits(32) for _ in range(8)]
    atk = Attack(master, 15, rng, model=model, fault="nibble")
    st = ColumnState()
    samples = []        # (equations in group, log2 candidates in group)
    for n in range(1, 121):
        atk.apply(st, atk.inject())
        for g in GROUP_COLUMNS:
            samples.append((sum(st.n_eq[p] for p in g), sum(math.log2(len(st.cands[p])) for p in g)))
    return samples


def exp_group_relation(trials: int, seed: int, workers: int) -> Dict:
    out = {"trials": trials, "seed": seed, "models": {}}
    with ProcessPoolExecutor(max_workers=workers) as ex:
        for model in ("paper", "full"):
            buckets: Dict[int, List[float]] = {}
            for samples in ex.map(_trial_group_relation, [(seed + i, model) for i in range(trials)],
                                  chunksize=max(1, trials // (8 * workers))):
                for e, l in samples:
                    buckets.setdefault(e, []).append(l)
            table = {}
            for e in sorted(buckets):
                v = buckets[e]
                table[e] = {"mean_log2": statistics.mean(v), "p95_log2": sorted(v)[math.ceil(0.95 * len(v)) - 1],
                            "max_log2": max(v), "frac_unique": statistics.mean(1.0 if x == 0 else 0.0 for x in v),
                            "samples": len(v)}
            out["models"][model] = table
            for e in (16, 20, 27, 36, 45, 54, 63):
                if e in table:
                    print(f"[E2] {model}: {e} equations -> mean 2^{table[e]['mean_log2']:.2f}, "
                          f"p95 2^{table[e]['p95_log2']:.1f}, unique in {100*table[e]['frac_unique']:.1f}%", flush=True)
    return out


# ---------------------------------------------------------------------------
# E3: equation probability per column, theory vs simulation
# ---------------------------------------------------------------------------
def exp_equation_probability(n_faults: int, seed: int) -> Dict:
    rng = random.Random(seed)
    master = [rng.getrandbits(32) for _ in range(8)]
    out = {}
    for fault in ("nibble", "nibble_aligned"):
        atk = Attack(master, 15, rng, model="full", fault=fault)
        counts = [0] * 32
        for _ in range(n_faults):
            pair = atk.inject()
            for p, _a in atk.constraints(pair):
                counts[p] += 1
        emp = [c / n_faults for c in counts]
        out[fault] = {"empirical": emp, "n_faults": n_faults}
    out["theory_sliding_window"] = equation_probability_theory(2)
    out["theory_aligned"] = [0.2] * 32
    err = max(abs(a - b) for a, b in zip(out["nibble"]["empirical"], out["theory_sliding_window"]))
    out["max_abs_error_sliding"] = err
    print(f"[E3] max |empirical - theory| over 32 columns = {err:.4f} ({n_faults} PNDs)")
    return out


# ---------------------------------------------------------------------------
# E4: end-to-end master key recovery
# ---------------------------------------------------------------------------
def _trial_master(args):
    seed, model, n_per_round = args
    rng = random.Random(seed)
    master = [rng.getrandbits(32) for _ in range(8)]
    mk = MasterKeyAttack(master, rng, model=model)
    if n_per_round == 0:        # adaptive: inject on each round until unique
        res = _adaptive_master(mk)
    else:
        res = mk.run(n_per_round, n_per_round, n_per_round, max_enum=1 << 18)
    res["seed"] = seed
    return res


def _adaptive_master(mk: MasterKeyAttack) -> Dict:
    """Inject on each round until its equivalent key is unique (no enumeration)."""
    t0 = time.perf_counter()
    known = {}
    total = 0
    t_solve = 0.0
    for r_inj, j in ((15, 3), (14, 2), (13, 1)):
        atk = mk.atk[r_inj]
        st = ColumnState()
        n = 0
        rks = list(mk.rks)
        for r, k in known.items():
            rks[r] = k
        while not st.unique() and n < MAX_FAULTS:
            delta = atk.sample_delta()
            pt = tuple(mk.rng.getrandbits(32) for _ in range(4))
            c = encrypt(pt, mk.rks)
            cf = encrypt(pt, mk.rks, fault=(r_inj, 3, delta))
            ts = time.perf_counter()
            pair = atk.pair_from_ciphertexts(c, cf, rks)
            atk.apply(st, pair)
            t_solve += time.perf_counter() - ts
            n += 1
        total += n
        known[r_inj + 1] = atk.recovered_round_key(st)
    from master_key_recovery import k16_from_k15_k14
    from aradi import master_from_key_state
    K16 = k16_from_k15_k14(known[15], known[14])
    ok = (K16[0], K16[1], K16[2], K16[3]) == tuple(known[16])
    master = master_from_key_state(K16, 16)
    ok = ok and master == mk.master
    return {"ok": ok, "faults": total, "t_total_s": time.perf_counter() - t0, "t_solve_s": t_solve,
            "log2_k16": 0.0, "k16_candidates_tested": 1}


def exp_master_key(trials: int, seed: int, workers: int) -> Dict:
    out = {"trials": trials, "seed": seed, "settings": {}}
    with ProcessPoolExecutor(max_workers=workers) as ex:
        for model, n in (("full", 36), ("full", 48), ("full", 0), ("paper", 0), ("paper", 72)):
            t0 = time.perf_counter()
            res = list(ex.map(_trial_master, [(seed + i, model, n) for i in range(trials)]))
            oks = [r.get("ok", False) for r in res]
            key = f"{model}_{'adaptive' if n == 0 else str(n) + 'per_round'}"
            summ = {"model": model, "faults_per_round": n, "success_rate": statistics.mean(1.0 if o else 0.0 for o in oks),
                    "n_failed": sum(1 for o in oks if not o),
                    "failures": [r for r in res if not r.get("ok", False)][:5],
                    "faults_total": percentiles([r["faults"] for r in res if "faults" in r]),
                    "log2_k16": percentiles([r["log2_k16"] for r in res if "log2_k16" in r]),
                    "k16_candidates_tested": percentiles([r["k16_candidates_tested"] for r in res if "k16_candidates_tested" in r]),
                    "solve_seconds": percentiles([r.get("t_solve_s", 0.0) for r in res]),
                    "pairs_to_reject_wrong_k16_mean": percentiles([r["mean_pairs_to_reject_wrong_k16"] for r in res if r.get("mean_pairs_to_reject_wrong_k16") is not None]) if any(r.get("mean_pairs_to_reject_wrong_k16") is not None for r in res) else None,
                    "pairs_to_reject_wrong_k16_max": max([r["max_pairs_to_reject_wrong_k16"] for r in res if r.get("max_pairs_to_reject_wrong_k16") is not None], default=None),
                    "seconds": time.perf_counter() - t0}
            out["settings"][key] = summ
            print(f"[E4] {key}: success {summ['success_rate']*100:.1f}%, faults {summ['faults_total']}, "
                  f"solve s {summ['solve_seconds']['mean']:.3f} ({summ['seconds']:.1f}s)", flush=True)
    return out


# ---------------------------------------------------------------------------
# E5: robustness of the PND filter against faults outside the model
# ---------------------------------------------------------------------------
def exp_filter_robustness(n: int, seed: int) -> Dict:
    rng = random.Random(seed)
    master = [rng.getrandbits(32) for _ in range(8)]
    rks, _ = expand_key(master)
    atk = Attack(master, 15, rng, model="full", fault="nibble")
    out = {}

    def run(kind, make_fault):
        accepted = 0
        wrong_constraint = 0
        for _ in range(n):
            pt = tuple(rng.getrandbits(32) for _ in range(4))
            faults = make_fault()
            c = encrypt(pt, rks)
            # apply possibly several faults: emulate by chaining encrypt with trace
            s = None
            # generic multi-fault encryption
            from aradi import xor_state, sbox_layer, linear_layer
            st = xor_state(pt, rks[0])
            for r in range(1, 17):
                for (fr, fw, fd) in faults:
                    if fr == r:
                        lst = list(st); lst[fw] ^= fd; st = tuple(lst)
                st = sbox_layer(*st); st = linear_layer((r - 1) % 4, *st); st = xor_state(st, rks[r])
            cf = st
            pair = atk.pair_from_ciphertexts(c, cf, rks)
            if pair.delta is not None:
                accepted += 1
                # does the accepted (wrong) hypothesis contradict the true key?
                for p, allowed in atk.constraints(pair):
                    k = atk.kappa_true[p]
                    from aradi import SBOX_INV
                    if (SBOX_INV[pair.c_tilde[p] ^ k] ^ SBOX_INV[pair.c_tilde_f[p] ^ k]) not in allowed:
                        wrong_constraint += 1
                        break
        out[kind] = {"n": n, "accepted": accepted, "accepted_rate": accepted / n,
                     "accepted_and_eliminates_true_key": wrong_constraint}
        print(f"[E5] {kind}: accepted {accepted}/{n}, of which harmful {wrong_constraint}", flush=True)

    def pnd():
        k = rng.randrange(29); v = rng.randrange(1, 16); return v << k
    run("single_pnd_in_z", lambda: [(15, 3, pnd())])
    run("two_pnds_in_z", lambda: [(15, 3, pnd() ^ pnd())])
    run("random_word_in_z", lambda: [(15, 3, rng.randrange(1, 1 << 32))])
    run("random_byte_window_in_z", lambda: [(15, 3, rng.randrange(1, 256) << rng.randrange(25))])
    run("pnd_in_z_and_pnd_in_x", lambda: [(15, 3, pnd()), (15, 1, pnd())])
    run("pnd_in_z_and_pnd_in_w", lambda: [(15, 3, pnd()), (15, 0, pnd())])
    run("pnd_in_z_wrong_round_14", lambda: [(14, 3, pnd())])
    run("pnd_in_z_wrong_round_16", lambda: [(16, 3, pnd())])
    run("three_bit_L2_preimage", lambda: [(15, 3, __import__('aradi').linear_map(2, 1 << rng.randrange(32)))])
    return out


# ---------------------------------------------------------------------------
# E6: structural facts (no randomness)
# ---------------------------------------------------------------------------
def exp_structure() -> Dict:
    out = {"pnd_count_distinct": len(pnd_set()), "pnd_sampling_pairs": 29 * 15, "linear_layers": {}, "windows": {}}
    for j in range(4):
        rep = collision_report(pnd_set(), j)
        rep["deltas_with_cancellation"] = [hex(d) for d in rep["deltas_with_cancellation"]]
        rep.pop("ambiguous_patterns")
        out["linear_layers"][j] = rep
    for width in range(1, 9):
        rep = collision_report(window_differences(width), 2)
        rep.pop("deltas_with_cancellation"); rep.pop("ambiguous_patterns")
        out["windows"][width] = rep
    return out



# ---------------------------------------------------------------------------
# E7: same plaintext for every injection (non-convergence)
# ---------------------------------------------------------------------------
def _trial_same_pt(args):
    seed, model, n_max = args
    rng = random.Random(seed)
    master = [rng.getrandbits(32) for _ in range(8)]
    atk = Attack(master, 15, rng, model=model, fault="nibble", same_plaintext=True)
    st = ColumnState()
    curve = []
    for n in range(1, n_max + 1):
        atk.apply(st, atk.inject())
        curve.append(round(st.log2_keyspace(), 4))
    return curve


def exp_same_plaintext(trials: int, seed: int, workers: int, n_max: int = 120) -> Dict:
    out = {"trials": trials, "seed": seed, "n_max": n_max, "models": {}}
    with ProcessPoolExecutor(max_workers=workers) as ex:
        for model in ("paper", "full"):
            curves = list(ex.map(_trial_same_pt, [(seed + i, model, n_max) for i in range(trials)],
                                 chunksize=max(1, trials // (8 * workers))))
            mean = [statistics.mean(c[i] for c in curves) for i in range(n_max)]
            mn = [min(c[i] for c in curves) for i in range(n_max)]
            mx = [max(c[i] for c in curves) for i in range(n_max)]
            out["models"][model] = {"mean_log2_keyspace": mean, "min_log2_keyspace": mn, "max_log2_keyspace": mx}
            print(f"[E7] same plaintext, {model}: log2 keyspace after 24/48/96/120 PNDs = "
                  f"{mean[23]:.1f}/{mean[47]:.1f}/{mean[95]:.1f}/{mean[119]:.1f} (mean), min after 120 = {mn[119]:.1f}", flush=True)
    return out

# ---------------------------------------------------------------------------
def save(name: str, obj: Dict) -> None:
    os.makedirs(RESULTS, exist_ok=True)
    obj["_machine"] = machine_info()
    obj["_timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(os.path.join(RESULTS, name + ".json"), "w") as f:
        json.dump(obj, f, indent=1)
    print(f"saved results/{name}.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("experiment", choices=["all", "structure", "faults_to_unique", "group_relation",
                                           "equation_probability", "master_key", "filter_robustness",
                                           "same_plaintext"])
    ap.add_argument("--trials", type=int, default=10000)
    ap.add_argument("--master-trials", type=int, default=500)
    ap.add_argument("--seed", type=int, default=20251101)
    ap.add_argument("--workers", type=int, default=os.cpu_count())
    a = ap.parse_args()
    print(f"seed={a.seed} trials={a.trials} workers={a.workers} machine={machine_info()}")
    t0 = time.perf_counter()
    if a.experiment in ("all", "structure"):
        save("structure", exp_structure())
    if a.experiment in ("all", "equation_probability"):
        save("equation_probability", exp_equation_probability(200000, a.seed))
    if a.experiment in ("all", "faults_to_unique"):
        save("faults_to_unique", exp_faults_to_unique(a.trials, a.seed, a.workers))
    if a.experiment in ("all", "group_relation"):
        save("group_relation", exp_group_relation(max(1, a.trials // 5), a.seed, a.workers))
    if a.experiment in ("all", "master_key"):
        save("master_key", exp_master_key(a.master_trials, a.seed, a.workers))
    if a.experiment in ("all", "filter_robustness"):
        save("filter_robustness", exp_filter_robustness(20000, a.seed))
    if a.experiment in ("all", "same_plaintext"):
        save("same_plaintext", exp_same_plaintext(max(1, a.trials // 10), a.seed, a.workers))
    print(f"total time {time.perf_counter() - t0:.1f}s")


if __name__ == "__main__":
    main()
