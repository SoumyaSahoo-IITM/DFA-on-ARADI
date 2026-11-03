"""
Regenerate the propagation tables of the paper from the cipher definition and
compare them with the LaTeX source.  Also emits LaTeX snippets into
results/tables/.

    python3 make_tables.py --tex /path/to/main_IEEE_IoT.tex
"""
from __future__ import annotations

import argparse
import os
import re
from typing import Dict, List, Tuple

from fault_model import bit_table, nibble_table, propagate_z, end_of_round_r_plus_1, supp
from aradi import linear_map

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "results", "tables")


def fmt(lst) -> str:
    return ", ".join(str(v) for v in lst)


def latex_bit_table(word: str = "z") -> str:
    rows = []
    for i, z15, a16 in bit_table(2, 3):
        others = [a for a in "wxyz" if a != word] if word == "z" else [a for a in "wxyz" if a != word]
        cert = f"$\\color{{red}}{{{word}^{{15}}[{fmt(z15)}]}}$"
        # for word z the x word is inactive; for word x all other words may be active
        if word == "z":
            rest = ", ".join(f"${a}^{{15}}[{fmt(z15)}]$" for a in ("y", "w"))
        else:
            rest = ", ".join(f"${a}^{{15}}[{fmt(z15)}]$" for a in ("y", "w", "z"))
        rows.append(f"${word}^{{14}}[{i}]$ & {cert}, {rest} & $a^{{16}}[{fmt(a16)}]$\\\\\n\\hline")
    return "\n".join(rows)


def latex_nibble_table(word: str = "z") -> str:
    rows = []
    for d, z15, a16 in nibble_table(2, 3):
        cert = f"$\\color{{red}}{word}^{{15}}[{fmt(z15)}]$"
        if word == "z":
            rest = ", ".join(f"${a}^{{15}}[{fmt(z15)}]$" for a in ("y", "w"))
        else:
            rest = ", ".join(f"${a}^{{15}}[{fmt(z15)}]$" for a in ("y", "w", "z"))
        rows.append(f"0x{d:08x} & {cert}, {rest} & [{fmt(a16)}]\\\\\n\\hline")
    return "\n".join(rows)


# --------------------------------------------------------------------------
# parse the manuscript's tables
# --------------------------------------------------------------------------
def parse_tex_tables(tex: str) -> Dict[str, List[Tuple[str, List[int], List[int]]]]:
    """Return for each table label a list of (first cell, certain-bit list, end-of-round-16 list)."""
    out = {}
    for m in re.finditer(r"\\begin\{table\*?\}.*?\\label\{([^}]*)\}(.*?)\\end\{table\*?\}", tex, re.S):
        label, body = m.group(1), m.group(2)
        if label not in ("tab: bit based propagation", "nibble based1",
                         "tab: bit based propagation in word x", "nibble based2_x"):
            continue
        rows = []
        for line in body.split("\n"):
            line = line.strip()
            if line.startswith("%") or "&" not in line or "Active Bits" in line or "Beginning" in line:
                continue
            cells = [c.strip() for c in line.split("&")]
            if len(cells) < 3:
                continue
            first = cells[0].replace("$", "")
            red = re.search(r"\\color\{red\}\{?([wxyz])\^\{15\}\[([^\]]*)\]", cells[1])
            if not red:
                continue
            cert = [int(v) for v in red.group(2).split(",") if v.strip()]
            last = cells[2].replace("\\\\", "").replace("\\hline", "")
            nums = re.findall(r"\d+", last.split("[", 1)[1] if "[" in last else last)
            end = [int(v) for v in nums]
            rows.append((first, cert, end))
        out[label] = rows
    return out


def compare(tex_path: str) -> List[str]:
    tex = open(tex_path, encoding="utf-8").read()
    tabs = parse_tex_tables(tex)
    report = []
    truth_bit = {f"z^{{14}}[{i}]": (list(z15), list(a16)) for i, z15, a16 in bit_table(2, 3)}
    truth_nib = {f"0x{d:08x}": (list(z15), list(a16)) for d, z15, a16 in nibble_table(2, 3)}
    for label, rows in tabs.items():
        truth = truth_bit if "bit" in label else truth_nib
        n_bad = 0
        for first, cert, end in rows:
            key = first.replace("x^{14}", "z^{14}").replace(" ", "")
            if key not in truth:
                report.append(f"{label}: row '{first}' not understood")
                continue
            tz, ta = truth[key]
            if cert != tz:
                n_bad += 1
                report.append(f"{label}: row {first}: certain bits {cert} should be {tz}")
            if end != ta:
                n_bad += 1
                report.append(f"{label}: row {first}: end-of-round-16 bits {end} should be {ta}")
        report.append(f"{label}: {len(rows)} rows checked, {n_bad} cell(s) differ from the computed table")
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--tex", default=None)
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    for name, txt in (("bit_table_z.tex", latex_bit_table("z")), ("bit_table_x.tex", latex_bit_table("x")),
                      ("nibble_table_z.tex", latex_nibble_table("z")), ("nibble_table_x.tex", latex_nibble_table("x"))):
        with open(os.path.join(OUT, name), "w") as f:
            f.write(txt + "\n")
    print("wrote LaTeX table bodies to", OUT)
    if a.tex:
        for line in compare(a.tex):
            print(line)
