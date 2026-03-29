#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gc
import json
import math
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np

MASK48 = (1 << 48) - 1
A48 = 0x5DEECE66D
C48 = 0xB
A31 = 214013
C31 = 2531011
MASK31 = 0x7FFFFFFF


def load_keyfile(path: str) -> Tuple[List[int], List[bytes]]:
    ids: List[int] = []
    keys: List[bytes] = []
    for lineno, raw in enumerate(Path(path).read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if ',' not in line:
            raise ValueError(f"{path}: line {lineno} is not badge_id,keyhex")
        bid, k = line.split(',', 1)
        ids.append(int(bid))
        keys.append(bytes.fromhex(k))
    if not keys:
        raise ValueError(f"{path}: no usable keys found")
    return ids, keys


def build_prefix_table(keys: List[bytes], prefix_keys: int) -> Tuple[Dict[bytes, List[int]], np.ndarray]:
    prefix_to_positions: Dict[bytes, List[int]] = defaultdict(list)
    prefix_len = prefix_keys * 10
    prefixes = []
    for i in range(0, len(keys) - prefix_keys + 1):
        p = b''.join(keys[i:i + prefix_keys])
        if len(p) != prefix_len:
            raise ValueError("bad prefix length")
        prefix_to_positions[p].append(i)
        prefixes.append(p)
    blob = b''.join(prefixes)
    arr = np.frombuffer(blob, dtype=np.uint8).reshape(len(prefixes), prefix_len)
    row_view = arr.view(np.dtype(f'V{prefix_len}')).reshape(-1)
    return prefix_to_positions, row_view


def drand48_first_nkeys(seeds: np.ndarray, nkeys: int) -> np.ndarray:
    x = ((seeds.astype(np.uint64) & 0xFFFFFFFF) << 16) + 0x330E
    out = np.empty((len(seeds), nkeys * 10), dtype=np.uint8)
    for i in range(nkeys * 10):
        x = (A48 * x + C48) & MASK48
        out[:, i] = ((x * 255) >> 48).astype(np.uint8)
    return out


def msvcrt_first_nkeys(seeds: np.ndarray, nkeys: int) -> np.ndarray:
    x = seeds.astype(np.uint64) & 0xFFFFFFFF
    out = np.empty((len(seeds), nkeys * 10), dtype=np.uint8)
    for i in range(nkeys * 10):
        x = (A31 * x + C31) & MASK31
        r = (x >> 16) & 0x7FFF
        out[:, i] = ((r * 255) >> 15).astype(np.uint8)
    return out


def drand48_stream(seed32: int, nkeys: int) -> List[bytes]:
    x = ((seed32 & 0xFFFFFFFF) << 16) + 0x330E
    out: List[bytes] = []
    for _ in range(nkeys):
        row = bytearray(10)
        for i in range(10):
            x = (A48 * x + C48) & MASK48
            row[i] = (x * 255) >> 48
        out.append(bytes(row))
    return out


def msvcrt_stream(seed32: int, nkeys: int) -> List[bytes]:
    x = seed32 & 0xFFFFFFFF
    out: List[bytes] = []
    for _ in range(nkeys):
        row = bytearray(10)
        for i in range(10):
            x = (A31 * x + C31) & MASK31
            r = (x >> 16) & 0x7FFF
            row[i] = (r * 255) >> 15
        out.append(bytes(row))
    return out


def stream_for_seed(model: str, seed32: int, nkeys: int) -> List[bytes]:
    if model == 'drand48':
        return drand48_stream(seed32, nkeys)
    if model == 'msvcrt':
        return msvcrt_stream(seed32, nkeys)
    raise ValueError(model)


def longest_run_from_start(file_keys: List[bytes], gen_keys: List[bytes], file_start: int) -> Dict[str, int]:
    n_file = len(file_keys)
    n_gen = len(gen_keys)
    max_len = min(n_file - file_start, n_gen)
    run = 0
    exact = 0
    while run < max_len and gen_keys[run] == file_keys[file_start + run]:
        exact += 1
        run += 1
    # after the first mismatch, still count exact matches over the remaining window
    for i in range(run, max_len):
        if gen_keys[i] == file_keys[file_start + i]:
            exact += 1
    return {
        'best_run_len': run,
        'total_exact_from_start': exact,
        'compared_len': max_len,
    }


def fmt_secs(secs: float) -> str:
    secs = max(0, int(secs))
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h:d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def maybe_write_jsonl(path: str | None, obj: dict):
    if not path:
        return
    with open(path, 'a', encoding='utf-8') as fh:
        fh.write(json.dumps(obj, separators=(',', ':')) + '\n')


def parse_seed(x: str) -> int:
    return int(x, 0)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--keyfile', required=True)
    ap.add_argument('--model', choices=['drand48', 'msvcrt'], default='drand48')
    ap.add_argument('--start-seed32', type=parse_seed, default=0)
    ap.add_argument('--end-seed32', type=parse_seed, default=0xFFFFFFFF)
    ap.add_argument('--chunk', type=int, default=2_000_000)
    ap.add_argument('--prefix-keys', type=int, default=2)
    ap.add_argument('--stream-keys', type=int, default=200)
    ap.add_argument('--top', type=int, default=100)
    ap.add_argument('--progress-every-sec', type=float, default=5.0)
    ap.add_argument('--checkpoint-jsonl')
    ap.add_argument('--report', required=True)
    args = ap.parse_args()

    ids, file_keys = load_keyfile(args.keyfile)
    prefix_to_positions, prefix_views = build_prefix_table(file_keys, args.prefix_keys)
    prefix_len = args.prefix_keys * 10

    first_nkeys = drand48_first_nkeys if args.model == 'drand48' else msvcrt_first_nkeys

    total_seeds = args.end_seed32 - args.start_seed32 + 1
    total_survivors = 0
    survivor_records = []

    t0 = time.time()
    last_progress = t0
    processed = 0
    chunk_index = 0

    for s in range(args.start_seed32, args.end_seed32 + 1, args.chunk):
        e = min(s + args.chunk - 1, args.end_seed32)
        seeds = np.arange(s, e + 1, dtype=np.uint64)
        arr = first_nkeys(seeds, args.prefix_keys)
        row_views = arr.view(np.dtype(f'V{prefix_len}')).reshape(-1)
        mask = np.isin(row_views, prefix_views, assume_unique=False)
        survivor_idx = np.flatnonzero(mask)
        total_survivors += int(len(survivor_idx))

        for idx in survivor_idx.tolist():
            seed32 = int(seeds[idx] & 0xFFFFFFFF)
            prefix_bytes = arr[idx].tobytes()
            survivor_records.append({
                'seed32': seed32,
                'candidate_file_starts': prefix_to_positions[prefix_bytes],
                'prefix_hex': prefix_bytes.hex(),
            })

        processed += len(seeds)
        chunk_index += 1
        now = time.time()
        if (now - last_progress) >= args.progress_every_sec or processed == total_seeds:
            elapsed = now - t0
            rate = processed / elapsed if elapsed else 0.0
            remaining = total_seeds - processed
            eta = remaining / rate if rate else 0.0
            progress = {
                'type': 'progress',
                'chunk_index': chunk_index,
                'processed': processed,
                'total_seeds': total_seeds,
                'pct': round((processed / total_seeds) * 100.0, 4),
                'elapsed_sec': round(elapsed, 3),
                'rate_seeds_per_sec': round(rate, 2),
                'eta_sec': round(eta, 1),
                'survivors_so_far': total_survivors,
            }
            print(
                f"[{progress['pct']:7.4f}%] processed={processed:,}/{total_seeds:,} "
                f"rate={rate/1e6:,.2f}M seeds/s survivors={total_survivors:,} eta={fmt_secs(eta)}"
            )
            maybe_write_jsonl(args.checkpoint_jsonl, progress)
            last_progress = now

        del seeds, arr, row_views, mask, survivor_idx
        gc.collect()

    # dedup identical seed32/prefix combos
    dedup_seen = set()
    deduped = []
    for rec in survivor_records:
        key = (rec['seed32'], rec['prefix_hex'])
        if key not in dedup_seen:
            dedup_seen.add(key)
            deduped.append(rec)

    scored = []
    for i, rec in enumerate(deduped, 1):
        seed32 = rec['seed32']
        gen_keys = stream_for_seed(args.model, seed32, args.stream_keys)
        best = None
        for file_start in rec['candidate_file_starts']:
            score = longest_run_from_start(file_keys, gen_keys, file_start)
            cand = {
                'model': args.model,
                'seed32': seed32,
                'file_start': file_start,
                'badge_id_at_start': ids[file_start],
                'prefix_hex': rec['prefix_hex'],
                **score,
            }
            if best is None or (
                cand['best_run_len'], cand['total_exact_from_start']
            ) > (
                best['best_run_len'], best['total_exact_from_start']
            ):
                best = cand
        if best is not None:
            scored.append(best)

        if i % 1000 == 0:
            maybe_write_jsonl(args.checkpoint_jsonl, {
                'type': 'scoring_progress',
                'done': i,
                'total': len(deduped),
            })

    scored.sort(
        key=lambda x: (x['best_run_len'], x['total_exact_from_start'], -x['file_start']),
        reverse=True,
    )

    elapsed = time.time() - t0
    out = {
        'model': args.model,
        'prefix_keys': args.prefix_keys,
        'stream_keys': args.stream_keys,
        'total_seeds': total_seeds,
        'chunk': args.chunk,
        'elapsed_sec': elapsed,
        'total_survivors': total_survivors,
        'candidate_count': len(deduped),
        'top': scored[:args.top],
    }
    Path(args.report).write_text(json.dumps(out, indent=2))
    print(f"wrote {args.report}")
    print(f"elapsed={fmt_secs(elapsed)} total_survivors={total_survivors:,} candidate_count={len(deduped):,}")
    print('top seeds:')
    for row in scored[:20]:
        print(row)


if __name__ == '__main__':
    main()
