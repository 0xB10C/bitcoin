#!/usr/bin/env python3
"""Replay a corpus through a fuzz target's cost meter, one input at a time, and
emit {sha1: measures} as JSON. Deterministic measures (alloc_bytes/count/max,
heap) are identical across runs of the same binary, so two replays of two
commits can be diffed by input hash to catch a change that makes a P2P path
more expensive. Timing is recorded too but is advisory (re-measure to confirm).

Usage:
  cost_replay.py --bin build_fuzz_nosan/bin/fuzz --target p2p_deserialize_cost \\
                 --type block --corpus .cache/full/block/corpus --out base.json
"""
import argparse, hashlib, json, os, subprocess, sys

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bin', required=True)
    ap.add_argument('--target', required=True)
    ap.add_argument('--type', default='')       # LIMIT_TO_MESSAGE_TYPE
    ap.add_argument('--corpus', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--limit', type=int, default=100000)
    ap.add_argument('--repeat', type=int, default=1)   # measure-mode time repeats
    a = ap.parse_args()

    files = []
    for root, _, names in os.walk(a.corpus):
        for n in names:
            files.append(os.path.join(root, n))
    files = files[:a.limit]

    env = dict(os.environ, FUZZ=a.target, FUZZ_COST_MODE='measure',
               FUZZ_COST_REPEAT=str(a.repeat))
    if a.target != 'p2p_deserialize_cost':
        env['FUZZ_COST_AUTO'] = '1'
    if a.type:
        env['LIMIT_TO_MESSAGE_TYPE'] = a.type

    out = {}
    # Batch files per exec for speed; each measure line is per input, in order.
    BATCH = 200
    for i in range(0, len(files), BATCH):
        chunk = files[i:i+BATCH]
        p = subprocess.run([a.bin, *chunk], env=env, capture_output=True, text=True, timeout=1800)
        lines = [l for l in (p.stdout + p.stderr).splitlines() if l.startswith('{') and '"bytes_in"' in l]
        # lines are in the same order the files were given
        for path, line in zip(chunk, lines):
            try: r = json.loads(line)
            except json.JSONDecodeError: continue
            h = hashlib.sha1(open(path, 'rb').read()).hexdigest()[:16]
            out[h] = r
    json.dump(out, open(a.out, 'w'))
    print(f'{len(out)} inputs measured -> {a.out}', file=sys.stderr)

if __name__ == '__main__':
    main()
