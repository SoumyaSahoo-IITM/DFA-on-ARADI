"""Per-equation survival probability of a wrong key offset eps for each
constraint type.  For the true kappa, the S-box inputs are a and a^d with d in
the allowed set D; a wrong candidate kappa^eps sees inputs S^-1(S(a)^eps) and
S^-1(S(a^d)^eps).  P_D(eps) = Pr_{a, d in D}[ that difference lies in D ]."""
from aradi import SBOX, SBOX_INV
from dfa_attack import allowed_set
import itertools

def survival(D):
    rows = []
    for eps in range(1, 16):
        n = 0; tot = 0
        for a in range(16):
            for d in D:
                b, bf = SBOX[a], SBOX[a ^ d]
                diff = SBOX_INV[b ^ eps] ^ SBOX_INV[bf ^ eps]
                tot += 1
                n += diff in D
        rows.append(n / tot)
    return rows

for name, D in [("paper  (dz=1)", allowed_set("paper", 1)),
                ("full   (dx=0,dz=1)", allowed_set("full", 1)),
                ("full   (dx=0,dz=0)", allowed_set("full", 0)),
                ("word   (dx=0)", allowed_set("word", None))]:
    s = survival(D)
    print(f"{name:20s} |D|={len(D):2d}  mean survival {sum(s)/15:.3f}  max {max(s):.3f}  per eps:", " ".join(f"{v:.2f}" for v in s))
