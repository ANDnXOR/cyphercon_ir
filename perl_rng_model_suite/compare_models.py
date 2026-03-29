from __future__ import annotations
import argparse
import time
from datetime import datetime, timezone
from pathlib import Path
import json
import gc

import numpy as np

from perl_rng_models import load_keyfile, dedup_hits_by_seed32, save_json

MASK48 = (1 << 48) - 1
A48 = 0x5DEECE66D
C48 = 0xB


def iso(seed32: int) -> str:
    return datetime.fromtimestamp(seed32 & 0xFFFFFFFF, tz=timezone.utc).isoformat()


def np_drand48_two(seeds: np.ndarray):
    x = ((seeds.astype(np.uint64) & 0xFFFFFFFF) << 16) + 0x330E
    x = (A48 * x + C48) & MASK48
    b1 = ((x * 255) >> 48).astype(np.uint8)
    x = (A48 * x + C48) & MASK48
    b2 = ((x * 255) >> 48).astype(np.uint8)
    return x, b1, b2


def np_drand48_bytes(seeds: np.ndarray, warmup_draws: int, nbytes: int = 10) -> np.ndarray:
    x = ((seeds.astype(np.uint64) & 0xFFFFFFFF) << 16) + 0x330E
    for _ in range(warmup_draws):
        x = (A48 * x + C48) & MASK48
    out = np.empty((len(seeds), nbytes), dtype=np.uint8)
    for i in range(nbytes):
        x = (A48 * x + C48) & MASK48
        out[:, i] = ((x * 255) >> 48).astype(np.uint8)
    return out


def np_msvcrt_two(seeds: np.ndarray):
    x = seeds.astype(np.uint64) & 0xFFFFFFFF
    x = (214013 * x + 2531011) & 0x7FFFFFFF
    r1 = (x >> 16) & 0x7FFF
    b1 = ((r1 * 255) >> 15).astype(np.uint8)
    x = (214013 * x + 2531011) & 0x7FFFFFFF
    r2 = (x >> 16) & 0x7FFF
    b2 = ((r2 * 255) >> 15).astype(np.uint8)
    return x, b1, b2


def np_msvcrt_bytes(seeds: np.ndarray, warmup_draws: int, nbytes: int = 10) -> np.ndarray:
    x = seeds.astype(np.uint64) & 0xFFFFFFFF
    for _ in range(warmup_draws):
        x = (214013 * x + 2531011) & 0x7FFFFFFF
    out = np.empty((len(seeds), nbytes), dtype=np.uint8)
    for i in range(nbytes):
        x = (214013 * x + 2531011) & 0x7FFFFFFF
        r = (x >> 16) & 0x7FFF
        out[:, i] = ((r * 255) >> 15).astype(np.uint8)
    return out


MODEL_MAP = {
    'drand48_520_plus': (np_drand48_two, np_drand48_bytes),
    'msvcrt_pre520': (np_msvcrt_two, np_msvcrt_bytes),
}


def search_model(model: str, positions_by_key: dict[bytes, list[int]], ids: list[int], keys: list[bytes],
                 start_seed32: int, end_seed32: int, chunk: int, warmup_min: int, warmup_max: int) -> dict:
    prefix_vals = np.array(sorted(set((k[0] << 8) | k[1] for k in keys)), dtype=np.uint16)
    two_func, bytes_func = MODEL_MAP[model]
    hits = []
    total_survivors = 0
    t0 = time.time()
    for warmup in range(warmup_min, warmup_max + 1):
        for s in range(start_seed32, end_seed32 + 1, chunk):
            e = min(s + chunk - 1, end_seed32)
            seeds = np.arange(s, e + 1, dtype=np.uint64)
            _x, b1, b2 = two_func(seeds)
            pref = ((b1.astype(np.uint16) << 8) | b2.astype(np.uint16))
            mask = np.isin(pref, prefix_vals, assume_unique=False)
            surv_idx = np.nonzero(mask)[0]
            total_survivors += len(surv_idx)
            if len(surv_idx):
                surv_seeds = seeds[surv_idx]
                out = bytes_func(surv_seeds, warmup, 10)
                for seedv, row in zip(surv_seeds.tolist(), out):
                    k = bytes(row.tolist())
                    if k in positions_by_key:
                        for pos in positions_by_key[k]:
                            hits.append({
                                'model': model,
                                'seed32': int(seedv & 0xFFFFFFFF),
                                'seed_iso': iso(int(seedv)),
                                'warmup_draws': warmup,
                                'file_pos': pos,
                                'badge_id': ids[pos],
                                'key_hex': k.hex(),
                            })
            del seeds, _x, b1, b2, pref, mask, surv_idx
            gc.collect()
    hits = dedup_hits_by_seed32(hits)
    return {
        'model': model,
        'start_seed32': start_seed32,
        'end_seed32': end_seed32,
        'warmup_min': warmup_min,
        'warmup_max': warmup_max,
        'survivors': total_survivors,
        'elapsed_sec': time.time() - t0,
        'hits': hits,
    }


def main():
    ap = argparse.ArgumentParser(description='Compare plausible Perl RNG models against the published keys file.')
    ap.add_argument('--keyfile', required=True)
    ap.add_argument('--models', nargs='+', default=['drand48_520_plus', 'msvcrt_pre520'])
    ap.add_argument('--start-seed32', type=lambda x: int(x, 0), default=0)
    ap.add_argument('--end-seed32', type=lambda x: int(x, 0), default=0xFFFFFFFF)
    ap.add_argument('--chunk', type=int, default=5_000_000)
    ap.add_argument('--warmup-min', type=int, default=0)
    ap.add_argument('--warmup-max', type=int, default=0)
    ap.add_argument('--report', required=True)
    args = ap.parse_args()

    ids, keys, positions_by_key = load_keyfile(args.keyfile)
    out = {
        'keyfile': str(Path(args.keyfile)),
        'entry_count': len(keys),
        'results': [],
    }
    for model in args.models:
        if model not in MODEL_MAP:
            raise SystemExit(f'Unknown model: {model}')
        out['results'].append(search_model(model, positions_by_key, ids, keys,
                                           args.start_seed32, args.end_seed32,
                                           args.chunk, args.warmup_min, args.warmup_max))
    save_json(args.report, out)
    print(f'wrote {args.report}')


if __name__ == '__main__':
    main()
