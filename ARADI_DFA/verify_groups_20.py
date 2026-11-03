"""Run the group/column equivalence check on 20 random instances with
different campaign sizes; writes results/group_equivalence.json."""
import json, random, time, io, contextlib
from dfa_attack import verify_group_equivalence
out = []
t0 = time.time()
for i in range(20):
    seed = 7000 + i
    n_faults = 6 + 2 * (i % 8)          # 6 .. 20 faults
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ok = verify_group_equivalence(seed=seed, n_faults=n_faults)
    out.append({"seed": seed, "n_faults": n_faults, "equal": ok})
    print(i, seed, n_faults, ok, flush=True)
json.dump({"instances": out, "all_equal": all(o["equal"] for o in out), "seconds": time.time() - t0},
          open("results/group_equivalence.json", "w"), indent=1)
print("all equal:", all(o["equal"] for o in out))
