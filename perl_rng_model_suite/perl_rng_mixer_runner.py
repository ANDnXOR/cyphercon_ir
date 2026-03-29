#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from collections import defaultdict
from typing import Callable

MASK48 = (1 << 48) - 1
A48 = 0x5DEECE66D
C48 = 0xB


def load_keyfile(path: Path):
    ids = []
    keys = []
    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if ',' not in line:
            raise ValueError(f"{path}: line {lineno} is not 'badge_id,keyhex': {line!r}")
        bid_s, key_hex = line.split(',', 1)
        ids.append(int(bid_s))
        keys.append(bytes.fromhex(key_hex))
    return ids, keys


def load_anchors(path: Path):
    data = json.loads(path.read_text())
    if isinstance(data, dict):
        if 'scored_hits' in data:
            return data['scored_hits']
        if 'ranked_hits' in data:
            return data['ranked_hits']
        if 'hits' in data:
            return data['hits']
    if isinstance(data, list):
        return data
    raise ValueError('anchors/scored-runs JSON must contain scored_hits, ranked_hits, hits, or be a list')


# ---- RNG cores ----
def gen_key_drand48(seed32: int, warmup_draws: int = 0) -> bytes:
    x = ((seed32 & 0xFFFFFFFF) << 16) + 0x330E
    for _ in range(warmup_draws):
        x = (A48 * x + C48) & MASK48
    out = bytearray(10)
    for i in range(10):
        x = (A48 * x + C48) & MASK48
        out[i] = (x * 255) >> 48
    return bytes(out)


def gen_key_msvcrt(seed32: int, warmup_draws: int = 0) -> bytes:
    x = seed32 & 0xFFFFFFFF
    for _ in range(warmup_draws):
        x = (214013 * x + 2531011) & 0x7FFFFFFF
    out = bytearray(10)
    for i in range(10):
        x = (214013 * x + 2531011) & 0x7FFFFFFF
        r = (x >> 16) & 0x7FFF
        out[i] = (r * 255) >> 15
    return bytes(out)


# ---- Seed mixers ----
def mix_identity(t: int, pid: int) -> int:
    return t & 0xFFFFFFFF


def mix_xor_pid(t: int, pid: int) -> int:
    return (t ^ pid) & 0xFFFFFFFF


def mix_add_pid(t: int, pid: int) -> int:
    return (t + pid) & 0xFFFFFFFF


def mix_xor_pid_hi(t: int, pid: int) -> int:
    return (t ^ ((pid & 0xFFFF) << 16)) & 0xFFFFFFFF


def mix_time_lo_pid_hi(t: int, pid: int) -> int:
    return ((t & 0xFFFF) | ((pid & 0xFFFF) << 16)) & 0xFFFFFFFF


def mix_pid_lo_time_hi(t: int, pid: int) -> int:
    return ((pid & 0xFFFF) | ((t & 0xFFFF) << 16)) & 0xFFFFFFFF


MIXERS: dict[str, Callable[[int, int], int]] = {
    'identity': mix_identity,
    'xor_pid': mix_xor_pid,
    'add_pid': mix_add_pid,
    'xor_pid_hi': mix_xor_pid_hi,
    'time_lo_pid_hi': mix_time_lo_pid_hi,
    'pid_lo_time_hi': mix_pid_lo_time_hi,
}

CORES = {
    'drand48': gen_key_drand48,
    'msvcrt': gen_key_msvcrt,
}


def parse_int_list(spec: str) -> list[int]:
    """Examples: '0', '0,1,2,4,8', '0:32', '0:32:2'"""
    spec = str(spec).strip()
    if ',' in spec:
        return [int(x, 0) for x in spec.split(',') if x.strip()]
    if ':' in spec:
        parts = [p for p in spec.split(':') if p != '']
        if len(parts) == 2:
            start, end = int(parts[0], 0), int(parts[1], 0)
            step = 1
        elif len(parts) == 3:
            start, end, step = int(parts[0], 0), int(parts[1], 0), int(parts[2], 0)
        else:
            raise ValueError(f'bad range spec: {spec}')
        return list(range(start, end + 1, step))
    return [int(spec, 0)]


def score_forward(ids, keys, start_pos: int, gen_keys: list[bytes], n: int):
    obs = keys[start_pos:min(len(keys), start_pos + n)]
    comp = min(len(obs), len(gen_keys))
    exact = 0
    longest = 0
    cur = 0
    prefix_total = 0
    matched_badges = []
    for i in range(comp):
        a = obs[i]
        b = gen_keys[i]
        prefix_total += sum(1 for x, y in zip(a, b) if x == y)
        if a == b:
            exact += 1
            cur += 1
            if cur > longest:
                longest = cur
            matched_badges.append(ids[start_pos + i])
        else:
            cur = 0
    return {
        'compared': comp,
        'exact_count': exact,
        'longest_contig': longest,
        'prefix_total': prefix_total,
        'matched_badges_exact': matched_badges,
    }


def build_session_window(core_name: str, mixed_seed32: int, warmup: int, skip_keys: int, nkeys: int):
    core = CORES[core_name]
    # advance by skip_keys whole keys
    gen = []
    # inefficient but simple and deterministic for small search windows
    for i in range(skip_keys + nkeys):
        k = core(mixed_seed32, warmup + i * 10)
        gen.append(k)
    return gen[skip_keys: skip_keys + nkeys]


def restart_hotspots(ids):
    # heuristic only, for report context
    spots = []
    for i in range(1, len(ids)):
        prev_id, cur_id = ids[i - 1], ids[i]
        if cur_id == prev_id:
            spots.append({'pos': i, 'reason': 'adjacent_duplicate', 'prev_id': prev_id, 'cur_id': cur_id})
        elif cur_id < prev_id and (prev_id - cur_id) > 20:
            spots.append({'pos': i, 'reason': 'large_backward_jump', 'prev_id': prev_id, 'cur_id': cur_id})
    return spots


def main():
    ap = argparse.ArgumentParser(description='Score Windows/Perl seed-mixer variants against anchor runs')
    ap.add_argument('--keyfile', required=True)
    ap.add_argument('--anchors-json', required=True, help='scored_runs.json / ranked_hits.json / anchors list')
    ap.add_argument('--cores', nargs='+', default=['drand48', 'msvcrt'])
    ap.add_argument('--mixers', nargs='+', default=['identity', 'xor_pid', 'add_pid', 'xor_pid_hi', 'time_lo_pid_hi', 'pid_lo_time_hi'])
    ap.add_argument('--pid-guesses', default='0,1,2,4,8,16,32,64,128,256,512,1024,2048,4096')
    ap.add_argument('--warmups', default='0:32')
    ap.add_argument('--skip-keys', default='0:32')
    ap.add_argument('--top-anchors', type=int, default=50)
    ap.add_argument('--min-forward-exact', type=int, default=0)
    ap.add_argument('--min-forward-longest', type=int, default=0)
    ap.add_argument('--compare-len', type=int, default=16, help='keys to compare forward from anchor file_pos')
    ap.add_argument('--report', required=True)
    args = ap.parse_args()

    keyfile = Path(args.keyfile)
    anchors_path = Path(args.anchors_json)
    ids, keys = load_keyfile(keyfile)
    anchors = load_anchors(anchors_path)

    # sort anchors strongest first if run scores are present
    def anchor_sort_key(a):
        return (
            int(a.get('forward_exact', a.get('forward', {}).get('exact', 0))),
            int(a.get('forward_longest_contig', a.get('forward', {}).get('longest_contig', 0))),
        )

    anchors = sorted(anchors, key=anchor_sort_key, reverse=True)[:args.top_anchors]

    pid_guesses = parse_int_list(args.pid_guesses)
    warmups = parse_int_list(args.warmups)
    skip_keys_vals = parse_int_list(args.skip_keys)

    t0 = time.time()
    model_rows = []
    best_per_anchor = []

    for anchor in anchors:
        seed32 = int(anchor['seed32']) & 0xFFFFFFFF
        file_pos = int(anchor['file_pos'])
        badge_id = int(anchor.get('badge_id', ids[file_pos]))
        expected_key_hex = anchor.get('key_hex', keys[file_pos].hex())
        anchor_best = []
        for core_name in args.cores:
            for mixer_name in args.mixers:
                mixer = MIXERS[mixer_name]
                for pid in pid_guesses:
                    mixed_seed32 = mixer(seed32, pid)
                    for warmup in warmups:
                        for skip_keys in skip_keys_vals:
                            gen_keys = build_session_window(core_name, mixed_seed32, warmup, skip_keys, args.compare_len)
                            score = score_forward(ids, keys, file_pos, gen_keys, args.compare_len)
                            row = {
                                'core': core_name,
                                'mixer': mixer_name,
                                'pid_guess': pid,
                                'warmup_draws': warmup,
                                'skip_keys': skip_keys,
                                'anchor_seed32': seed32,
                                'anchor_file_pos': file_pos,
                                'anchor_badge_id': badge_id,
                                'anchor_key_hex': expected_key_hex,
                                **score,
                            }
                            if score['exact_count'] >= args.min_forward_exact and score['longest_contig'] >= args.min_forward_longest:
                                model_rows.append(row)
                                anchor_best.append(row)
        anchor_best = sorted(anchor_best, key=lambda r: (r['longest_contig'], r['exact_count'], r['prefix_total']), reverse=True)
        best_per_anchor.append({
            'anchor_seed32': seed32,
            'anchor_file_pos': file_pos,
            'anchor_badge_id': badge_id,
            'anchor_key_hex': expected_key_hex,
            'top': anchor_best[:20],
        })

    # aggregate model totals
    summary = defaultdict(lambda: {'anchor_count': 0, 'exact_sum': 0, 'longest_sum': 0, 'best_longest': 0, 'best_exact': 0})
    seen_anchor_model = set()
    for row in model_rows:
        k = (row['core'], row['mixer'], row['pid_guess'], row['warmup_draws'], row['skip_keys'])
        s = summary[k]
        s['exact_sum'] += row['exact_count']
        s['longest_sum'] += row['longest_contig']
        s['best_longest'] = max(s['best_longest'], row['longest_contig'])
        s['best_exact'] = max(s['best_exact'], row['exact_count'])
        ak = (k, row['anchor_file_pos'])
        if ak not in seen_anchor_model:
            seen_anchor_model.add(ak)
            s['anchor_count'] += 1

    model_summary = []
    for k, s in summary.items():
        core, mixer, pid_guess, warmup_draws, skip_keys = k
        model_summary.append({
            'core': core,
            'mixer': mixer,
            'pid_guess': pid_guess,
            'warmup_draws': warmup_draws,
            'skip_keys': skip_keys,
            **s,
        })
    model_summary.sort(key=lambda r: (r['anchor_count'], r['best_longest'], r['exact_sum'], r['longest_sum']), reverse=True)

    out = {
        'meta': {
            'entry_count': len(keys),
            'anchor_count_used': len(anchors),
            'elapsed_sec': time.time() - t0,
            'compare_len': args.compare_len,
            'pid_guesses': pid_guesses,
            'warmups': warmups,
            'skip_keys_values': skip_keys_vals,
            'cores': args.cores,
            'mixers': args.mixers,
            'restart_hotspots': restart_hotspots(ids)[:100],
        },
        'model_summary': model_summary[:200],
        'best_per_anchor': best_per_anchor,
    }

    Path(args.report).write_text(json.dumps(out, indent=2))
    print(f"wrote {args.report}")
    if model_summary:
        print('top models:')
        for row in model_summary[:20]:
            print(row)


if __name__ == '__main__':
    main()
