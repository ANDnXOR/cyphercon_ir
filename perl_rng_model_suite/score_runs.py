from __future__ import annotations
import argparse
from pathlib import Path
from collections import defaultdict

from perl_rng_models import load_keyfile, MODEL_FUNCS, save_json


def longest_contig(obs, gen):
    longest = 0
    cur = 0
    for a, b in zip(obs, gen):
        if a == b:
            cur += 1
            longest = max(longest, cur)
        else:
            cur = 0
    return longest


def generate_stream(model: str, seed32: int, warmup_draws: int, nkeys: int, key_index_offset: int = 0):
    # key_index_offset skips whole keys (10 draws per key)
    warmup_total = warmup_draws + key_index_offset * 10
    fn = MODEL_FUNCS[model]
    out = []
    for i in range(nkeys):
        out.append(fn(seed32, warmup_draws=warmup_total + i * 10))
    return out


def discover_islands(ids: list[int]) -> list[dict]:
    islands = []
    n = len(ids)
    # duplicate clusters
    pos_by_id = defaultdict(list)
    for i, bid in enumerate(ids):
        pos_by_id[bid].append(i)
    for bid, poss in pos_by_id.items():
        if len(poss) >= 2:
            s = max(0, min(poss) - 5)
            e = min(n - 1, max(poss) + 5)
            islands.append({'name': f'dup_id_{bid}', 'start': s, 'end': e, 'kind': 'duplicate'})
    # ascending runs
    start = 0
    for i in range(1, n):
        if ids[i] != ids[i - 1] + 1:
            if i - start >= 12:
                islands.append({'name': f'ascending_{start}_{i-1}', 'start': start, 'end': i - 1, 'kind': 'ascending'})
            start = i
    if n - start >= 12:
        islands.append({'name': f'ascending_{start}_{n-1}', 'start': start, 'end': n - 1, 'kind': 'ascending'})
    # tail block
    if n >= 12:
        islands.append({'name': 'tail_repair', 'start': max(0, n - 12), 'end': n - 1, 'kind': 'tail'})
    # dedup by range
    seen = set()
    out = []
    for isl in islands:
        t = (isl['start'], isl['end'], isl['name'])
        if t not in seen:
            seen.add(t)
            out.append(isl)
    return sorted(out, key=lambda x: (x['start'], x['end'], x['name']))


def score_anchor(anchor: dict, ids: list[int], keys: list[bytes], radius: int = 12) -> dict:
    pos = anchor['file_pos']
    start = max(0, pos - radius)
    end = min(len(keys), pos + radius + 1)
    obs = keys[start:end]
    key_offset = pos - start
    gen = generate_stream(anchor['model'], anchor['seed32'], anchor.get('warmup_draws', 0), len(obs), key_index_offset=0)
    exact = sum(1 for a, b in zip(obs[key_offset:], gen[:len(obs[key_offset:])]) if a == b)
    longest = longest_contig(obs[key_offset:], gen[:len(obs[key_offset:])])
    return {
        **anchor,
        'window_start': start,
        'window_end': end - 1,
        'forward_exact': exact,
        'forward_longest_contig': longest,
        'observed_badges': ids[start:end],
    }


def main():
    ap = argparse.ArgumentParser(description='Score file-order runs around exact-hit anchors.')
    ap.add_argument('--keyfile', required=True)
    ap.add_argument('--hits-json', required=True)
    ap.add_argument('--radius', type=int, default=12)
    ap.add_argument('--report', required=True)
    args = ap.parse_args()

    ids, keys, _ = load_keyfile(args.keyfile)
    hits_obj = __import__('json').loads(Path(args.hits_json).read_text())
    hits = []
    for r in hits_obj.get('results', []):
        hits.extend(r.get('hits', []))
    scored = [score_anchor(h, ids, keys, radius=args.radius) for h in hits]
    scored.sort(key=lambda x: (x['forward_longest_contig'], x['forward_exact']), reverse=True)
    out = {
        'entry_count': len(keys),
        'islands': discover_islands(ids),
        'scored_hits': scored,
    }
    save_json(args.report, out)
    print(f'wrote {args.report}')


if __name__ == '__main__':
    main()
