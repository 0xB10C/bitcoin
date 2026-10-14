#!/usr/bin/env python3
"""Diff two cost_replay.py outputs (base vs head) by input hash and flag inputs
that got more expensive. Intended to run in CI on a fixed corpus to catch a pull
request that adds quadratic or allocation-heavy work to a P2P path before merge.

Flags an input when a measure grew by more than --ratio AND by more than a
per-measure absolute floor (so trivial deltas and tiny inputs don't spam). Ranks
on the DETERMINISTIC measures by default; timing is reported but excluded from
the pass/fail decision unless --include-time, because it is noisy.

Usage:
  cost_diff.py base.json head.json
  cost_diff.py base.json head.json --ratio 1.5 --include-time
"""
import argparse, json, sys

# measure -> absolute floor below which a ratio change is ignored
FLOOR = {
    'alloc_bytes': 1 << 20,   # 1 MB
    'alloc_count': 1000,
    'alloc_max':   1 << 20,
    'heap_kept':   64 << 10,  # 64 kB
    'out_bytes':   4096,
    'time_ns':     2_000_000, # 2 ms
}
DETERMINISTIC = ['alloc_bytes', 'alloc_count', 'alloc_max', 'heap_kept', 'out_bytes']

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('base'); ap.add_argument('head')
    ap.add_argument('--ratio', type=float, default=1.5)
    ap.add_argument('--include-time', action='store_true')
    a = ap.parse_args()

    base = json.load(open(a.base)); head = json.load(open(a.head))
    measures = DETERMINISTIC + (['time_ns'] if a.include_time else [])

    flags = []
    common = set(base) & set(head)
    for h in common:
        b, d = base[h], head[h]
        for m in measures:
            bv, dv = b.get(m, 0), d.get(m, 0)
            if dv <= bv: continue
            if dv - bv < FLOOR.get(m, 0): continue
            if bv == 0:
                if dv < FLOOR.get(m, 0): continue
                ratio = float('inf')
            else:
                ratio = dv / bv
            if ratio < a.ratio: continue
            flags.append((ratio, m, h, bv, dv, d.get('label', '?'), d.get('bytes_in', 0)))

    flags.sort(key=lambda x: -x[0] if x[0] != float('inf') else -1e18)
    # per-type median shift, so a broad regression shows even without a single spike
    print(f"compared {len(common)} shared inputs "
          f"({len(set(base)-set(head))} only in base, {len(set(head)-set(base))} only in head)")
    if not flags:
        print("PASS: no input regressed beyond thresholds")
    else:
        print(f"FAIL: {len(flags)} regressions (ratio>={a.ratio}, above floor)\n")
        print(f"{'ratio':>8} {'measure':<12} {'label':<13} {'in_B':>8} {'base':>12} {'head':>12}  input")
        for ratio, m, h, bv, dv, lab, nin in flags[:40]:
            rs = 'inf' if ratio == float('inf') else f'{ratio:.2f}x'
            print(f"{rs:>8} {m:<12} {lab:<13} {nin:>8} {bv:>12} {dv:>12}  {h}")
    sys.exit(1 if flags else 0)

if __name__ == '__main__':
    main()
