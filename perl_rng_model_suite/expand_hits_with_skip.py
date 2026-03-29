from __future__ import annotations
import argparse
import json
from pathlib import Path
from collections import defaultdict
import time

from perl_rng_models import load_keyfile, MODEL_FUNCS, save_json


def discover_islands(ids: list[int], dup_radius: int = 20, run_radius: int = 8) -> list[dict]:
    n = len(ids)
    islands = []
    pos_by_id = defaultdict(list)
    for i, bid in enumerate(ids):
        pos_by_id[bid].append(i)
    for bid, poss in pos_by_id.items():
        if len(poss) >= 2:
            s = max(0, min(poss) - dup_radius)
            e = min(n - 1, max(poss) + dup_radius)
            islands.append({'name': f'dup_id_{bid}', 'start': s, 'end': e, 'kind': 'duplicate'})
    start = 0
    for i in range(1, n):
        if ids[i] != ids[i-1] + 1:
            if i - start >= 12:
                center = (start + i - 1) // 2
                islands.append({'name': f'ascending_{start}_{i-1}', 'start': start, 'end': i - 1, 'kind': 'ascending'})
                islands.append({'name': f'run_center_{center}', 'start': max(0, center-run_radius), 'end': min(n-1, center+run_radius), 'kind': 'run_center'})
            start = i
    if n - start >= 12:
        center = (start + n - 1) // 2
        islands.append({'name': f'ascending_{start}_{n-1}', 'start': start, 'end': n - 1, 'kind': 'ascending'})
        islands.append({'name': f'run_center_{center}', 'start': max(0, center-run_radius), 'end': min(n-1, center+run_radius), 'kind': 'run_center'})
    islands.append({'name': 'tail_repair', 'start': max(0, n-12), 'end': n-1, 'kind': 'tail'})
    seen = set(); out=[]
    for isl in islands:
        t=(isl['name'], isl['start'], isl['end'])
        if t not in seen:
            seen.add(t); out.append(isl)
    return sorted(out, key=lambda x:(x['start'], x['end'], x['name']))


def key_from_model(model: str, seed32: int, total_draw_offset: int) -> bytes:
    return MODEL_FUNCS[model](seed32, warmup_draws=total_draw_offset)


def score_one_island(model: str, seed32: int, warmup_draws: int, island: dict, keys: list[bytes], skip_keys: int):
    obs = keys[island['start']:island['end']+1]
    gen = [key_from_model(model, seed32, warmup_draws + (skip_keys + i) * 10) for i in range(len(obs))]
    exact = sum(1 for a,b in zip(obs, gen) if a == b)
    longest = 0; cur = 0
    prefix_total = 0
    for a,b in zip(obs, gen):
        pref = 0
        for x,y in zip(a,b):
            if x == y:
                pref += 1
            else:
                break
        prefix_total += pref
        if a == b:
            cur += 1; longest = max(longest, cur)
        else:
            cur = 0
    return {'exact_count': exact, 'longest_contig': longest, 'prefix_total': prefix_total}


def main():
    ap = argparse.ArgumentParser(description='Expand exact-hit anchors across auto-discovered islands with key skips.')
    ap.add_argument('--keyfile', required=True)
    ap.add_argument('--scored-hits-json', required=True)
    ap.add_argument('--skip-keys-min', type=int, default=0)
    ap.add_argument('--skip-keys-max', type=int, default=500)
    ap.add_argument('--top-anchors', type=int, default=100)
    ap.add_argument('--top-per-island', type=int, default=25)
    ap.add_argument('--report', required=True)
    args = ap.parse_args()

    ids, keys, _ = load_keyfile(args.keyfile)
    obj = json.loads(Path(args.scored_hits_json).read_text())
    anchors = obj.get('scored_hits', [])[:args.top_anchors]
    islands = discover_islands(ids)
    results = []
    t0 = time.time()
    for anchor in anchors:
        for skip_keys in range(args.skip_keys_min, args.skip_keys_max + 1):
            for island in islands:
                score = score_one_island(anchor['model'], anchor['seed32'], anchor.get('warmup_draws', 0), island, keys, skip_keys)
                if score['exact_count'] or score['longest_contig'] >= 2 or score['prefix_total'] >= 8:
                    results.append({**anchor, 'skip_keys': skip_keys, 'island': island, **score})
    results.sort(key=lambda x:(x['longest_contig'], x['exact_count'], x['prefix_total']), reverse=True)
    out = {
        'elapsed_sec': time.time() - t0,
        'island_count': len(islands),
        'result_count': len(results),
        'global_top': results[:max(args.top_per_island, 100)],
        'all_results': results,
    }
    save_json(args.report, out)
    print(f'wrote {args.report}')


if __name__ == '__main__':
    main()
