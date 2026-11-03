"""
Turn results/*.json into the LaTeX tables of the paper (results/tables/*.tex)
and a Markdown summary (results/summary.md).
"""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results")
OUT = os.path.join(RES, "tables")


def load(name):
    with open(os.path.join(RES, name + ".json")) as f:
        return json.load(f)


def w(name, txt):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, name), "w") as f:
        f.write(txt)


def table_faults(ftu):
    c = ftu["configs"]
    rows = [
        ("Nibble (PND), conditions $\\Delta z=1$ only (earlier version)", "paper_nibble_r15"),
        ("Nibble (PND), conditions \\eqref{eq:membership}", "full_nibble_r15"),
        ("\\quad same, aligned nibbles only", "full_nibble_aligned_r15"),
        ("\\quad same, injection at round 14 ($k_{15}$)", "full_nibble_r14"),
        ("\\quad same, injection at round 13 ($k_{14}$)", "full_nibble_r13"),
        ("Single bit", "full_bit_r15"),
        ("Byte window (8 adjacent bits)", "full_byte_r15"),
        ("Whole word (random 32-bit value)", "word_word_r15"),
    ]
    lines = []
    for label, key in rows:
        if key not in c:
            continue
        s = c[key]["faults_to_unique"]
        lines.append(f"{label} & {s['mean']:.1f} & {s['p50']:.0f} & {s['p90']:.0f} & {s['p95']:.0f} & {s['p99']:.0f} & {s['max']:.0f} \\\\")
    body = "\n".join(lines)
    n = ftu["trials"]
    return f"""\\begin{{table}}[ht!]
\\centering
\\caption{{Number of fault injections until the equivalent key of the attacked round is unique in all $32$ columns ({n:,} random keys per row, fresh plaintext per injection).}}
\\label{{tab:faults}}
\\renewcommand{{\\arraystretch}}{{1.2}}
\\resizebox{{\\columnwidth}}{{!}}{{
\\begin{{tabular}}{{lrrrrrr}}
\\toprule
Fault model & mean & median & 90\\% & 95\\% & 99\\% & max \\\\
\\midrule
{body}
\\bottomrule
\\end{{tabular}}}}
\\end{{table}}
""", {k: c[k]["faults_to_unique"] for k in c}


def table_keyspace(ftu):
    c = ftu["configs"]
    pts = [24, 30, 36, 42, 48, 60, 72, 96]
    lines = []
    for f in pts:
        cells = [str(f)]
        for key in ("paper_nibble_r15", "full_nibble_r15"):
            cfg = c[key]
            i = f - 1
            if i >= len(cfg["mean_log2_keyspace"]):
                cells += ["--", "--", "--", "--"]
                continue
            cells += [f"{cfg['mean_log2_keyspace'][i]:.1f}", f"{cfg['p95_log2_keyspace'][i]:.1f}",
                      f"{cfg['max_log2_keyspace'][i]:.1f}", f"{100*cfg['frac_unique'][i]:.0f}\\%"]
        lines.append(" & ".join(cells) + " \\\\")
    body = "\n".join(lines)
    return f"""\\begin{{table}}[ht!]
\\centering
\\caption{{Residual key space of the last-round key after $f$ random PNDs: $\\log_2$ of the number of candidates (mean, 95th percentile, maximum over {ftu['trials']:,} keys) and fraction of keys for which the round key is already unique.}}
\\label{{tab:keyspace}}
\\renewcommand{{\\arraystretch}}{{1.2}}
\\resizebox{{\\columnwidth}}{{!}}{{
\\begin{{tabular}}{{r|rrrr|rrrr}}
\\toprule
 & \\multicolumn{{4}}{{c|}}{{$\\Delta z=1$ only (earlier version)}} & \\multicolumn{{4}}{{c}}{{conditions \\eqref{{eq:membership}}}} \\\\
$f$ & mean & 95\\% & max & unique & mean & 95\\% & max & unique \\\\
\\midrule
{body}
\\bottomrule
\\end{{tabular}}}}
\\end{{table}}
"""


def table_groups(gr):
    pts = [12, 16, 20, 27, 36, 45, 54, 63]
    lines = []
    for e in pts:
        cells = [str(e)]
        for model in ("paper", "full"):
            t = gr["models"][model].get(str(e))
            if t is None:
                cells += ["--", "--"]
            else:
                cells += [f"{t['mean_log2']:.2f}", f"{100*t['frac_unique']:.0f}\\%"]
        lines.append(" & ".join(cells) + " \\\\")
    body = "\n".join(lines)
    return f"""\\begin{{table}}[ht!]
\\centering
\\caption{{Candidates for the $16$ key bits of one group as a function of the number of active-column conditions the group has received ($\\log_2$, mean over all groups and {gr['trials']:,} keys; ``unique'' is the fraction of groups with one candidate).}}
\\label{{tab:group_relation}}
\\renewcommand{{\\arraystretch}}{{1.2}}
\\begin{{tabular}}{{r|rr|rr}}
\\toprule
 & \\multicolumn{{2}}{{c|}}{{$\\Delta z=1$ only}} & \\multicolumn{{2}}{{c}}{{conditions \\eqref{{eq:membership}}}} \\\\
conditions & $\\log_2$ cand. & unique & $\\log_2$ cand. & unique \\\\
\\midrule
{body}
\\bottomrule
\\end{{tabular}}
\\end{{table}}
"""


def table_probabilities(ep):
    th = ep["theory_sliding_window"]
    emp = ep["nibble"]["empirical"]
    rows = []
    for r in range(8):
        cells = []
        for cidx in range(4):
            p = r + 8 * cidx
            cells.append(f"$z^{{15}}[{p}]$ & {th[p]:.3f} & {emp[p]:.3f}")
        rows.append(" & ".join(cells) + " \\\\")
    body = "\n".join(rows)
    return f"""\\begin{{table}}[ht!]
\\centering
\\caption{{Probability that one random PND makes column $p$ of $z^{{15}}$ active (closed form \\eqref{{eq:prob}} and simulation with $2\\times 10^5$ PNDs).}}
\\label{{tab:equ_probabilities}}
\\renewcommand{{\\arraystretch}}{{1.15}}
\\resizebox{{\\columnwidth}}{{!}}{{
\\begin{{tabular}}{{l rr|l rr|l rr|l rr}}
\\toprule
$p$ & theory & sim. & $p$ & theory & sim. & $p$ & theory & sim. & $p$ & theory & sim. \\\\
\\midrule
{body}
\\bottomrule
\\end{{tabular}}}}
\\end{{table}}
"""


def table_master(mk):
    st = mk["settings"]
    order = [("full_36per_round", "$36+36+36$", "conditions \\eqref{eq:membership}"),
             ("full_48per_round", "$48+48+48$", "conditions \\eqref{eq:membership}"),
             ("full_adaptive", "until unique", "conditions \\eqref{eq:membership}"),
             ("paper_72per_round", "$72+72+72$", "$\\Delta z=1$ only"),
             ("paper_adaptive", "until unique", "$\\Delta z=1$ only")]
    lines = []
    for key, faults, model in order:
        if key not in st:
            continue
        r = st[key]
        ft = r["faults_total"]
        k16 = r["log2_k16"]
        tested = r["k16_candidates_tested"]
        ts = r["solve_seconds"]
        lines.append(f"{model} & {faults} & {100*r['success_rate']:.1f}\\% & {ft['mean']:.0f} & {ft['max']:.0f} & "
                     f"{k16['mean']:.1f} & {k16['max']:.1f} & {tested['mean']:.0f} & {tested['max']:.0f} & {1000*ts['mean']:.0f} & {1000*ts['max']:.0f} \\\\")
    body = "\n".join(lines)
    return f"""\\begin{{table*}}[ht!]
\\centering
\\caption{{End-to-end recovery of the $256$-bit master key ({mk['trials']:,} random keys per row). Faults: total number of PNDs over the three campaigns. $\\log_2|\\mathcal{{K}}_{{16}}|$: residual key space after campaign~1. Tested: number of candidates for $k_{{16}}$ on which campaign~2 was run. Time: attacker-side computation (identification, filtering, enumeration, key-schedule inversion).}}
\\label{{tab:master}}
\\renewcommand{{\\arraystretch}}{{1.2}}
\\begin{{tabular}}{{llr rr rr rr rr}}
\\toprule
 & & & \\multicolumn{{2}}{{c}}{{faults}} & \\multicolumn{{2}}{{c}}{{$\\log_2|\\mathcal{{K}}_{{16}}|$}} & \\multicolumn{{2}}{{c}}{{tested}} & \\multicolumn{{2}}{{c}}{{time (ms)}} \\\\
conditions & faults per campaign & success & mean & max & mean & max & mean & max & mean & max \\\\
\\midrule
{body}
\\bottomrule
\\end{{tabular}}
\\end{{table*}}
"""


def table_filter(fr):
    order = [("single_pnd_in_z", "one PND in $z$ (the model)"),
             ("two_pnds_in_z", "two independent PNDs in $z$"),
             ("random_byte_window_in_z", "random byte window in $z$"),
             ("random_word_in_z", "random 32-bit value in $z$"),
             ("pnd_in_z_and_pnd_in_x", "PND in $z$ and PND in $x$"),
             ("pnd_in_z_and_pnd_in_w", "PND in $z$ and PND in $w$"),
             ("pnd_in_z_wrong_round_14", "PND in $z$, one round too early"),
             ("pnd_in_z_wrong_round_16", "PND in $z$, one round too late"),
             ("three_bit_L2_preimage", "$L_2(e_q)$: three spread bits in $z$")]
    lines = []
    for key, label in order:
        if key not in fr:
            continue
        r = fr[key]
        lines.append(f"{label} & {100*r['accepted_rate']:.1f}\\% & {100*r['accepted_and_eliminates_true_key']/r['n']:.1f}\\% \\\\")
    body = "\n".join(lines)
    n = fr["single_pnd_in_z"]["n"]
    return f"""\\begin{{table}}[ht!]
\\centering
\\caption{{Behaviour of the PND filter (\\autoref{{prop:unique}}) under faults outside the model ({n:,} injections each). Accepted: the pair passes the filter. Harmful: accepted and the derived conditions \\eqref{{eq:membership}} exclude the true key.}}
\\label{{tab:filter}}
\\renewcommand{{\\arraystretch}}{{1.2}}
\\begin{{tabular}}{{lrr}}
\\toprule
injected fault & accepted & harmful \\\\
\\midrule
{body}
\\bottomrule
\\end{{tabular}}
\\end{{table}}
"""


def main():
    md = []
    ftu = load("faults_to_unique")
    t, summary = table_faults(ftu)
    w("tab_faults.tex", t)
    w("tab_keyspace.tex", table_keyspace(ftu))
    md.append("## faults to unique\n")
    for k, v in summary.items():
        md.append(f"- {k}: mean {v['mean']:.1f}, median {v['p50']}, p90 {v['p90']}, p95 {v['p95']}, p99 {v['p99']}, max {v['max']}")
    try:
        gr = load("group_relation")
        w("tab_group_relation.tex", table_groups(gr))
        md.append("\n## group relation (equations -> log2 candidates, % unique)\n")
        for model in ("paper", "full"):
            for e in (16, 20, 27, 36, 45):
                tt = gr["models"][model].get(str(e))
                if tt:
                    md.append(f"- {model}: {e} eq -> 2^{tt['mean_log2']:.2f}, unique {100*tt['frac_unique']:.1f}%")
    except FileNotFoundError:
        pass
    ep = load("equation_probability")
    w("tab_probabilities.tex", table_probabilities(ep))
    md.append(f"\n## equation probability: max |emp-theory| = {ep['max_abs_error_sliding']:.4f}")
    try:
        mk = load("master_key")
        w("tab_master.tex", table_master(mk))
        md.append("\n## master key\n")
        for k, r in mk["settings"].items():
            md.append(f"- {k}: success {100*r['success_rate']:.1f}%, faults mean {r['faults_total']['mean']:.0f} max {r['faults_total']['max']}, "
                      f"log2 k16 mean {r['log2_k16']['mean']:.2f} max {r['log2_k16']['max']:.1f}, tested mean {r['k16_candidates_tested']['mean']:.1f} max {r['k16_candidates_tested']['max']}, "
                      f"solve ms mean {1000*r['solve_seconds']['mean']:.1f} max {1000*r['solve_seconds']['max']:.1f}, "
                      f"pairs to reject wrong k16: {r.get('pairs_to_reject_wrong_k16_mean')} max {r.get('pairs_to_reject_wrong_k16_max')}")
    except FileNotFoundError:
        pass
    try:
        fr = load("filter_robustness")
        w("tab_filter.tex", table_filter(fr))
        md.append("\n## filter robustness\n")
        for k, r in fr.items():
            if k.startswith("_"):
                continue
            md.append(f"- {k}: accepted {100*r['accepted_rate']:.2f}%, harmful {r['accepted_and_eliminates_true_key']}/{r['n']}")
    except FileNotFoundError:
        pass
    with open(os.path.join(RES, "summary.md"), "w") as f:
        f.write("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
