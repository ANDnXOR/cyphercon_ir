#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from collections import defaultdict
import argparse
import json
import gc
import numpy as np

MASK48 = (1 << 48) - 1
A48 = 0x5DEECE66D
C48 = 0xB

A31 = 214013
C31 = 2531011
MASK31 = 0x7FFFFFFF


def load_keyfile(path: str):
    ids = []
    keys = []
    for lineno, raw in enumerate(Path(path).read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "," not in line:
            raise ValueError(f"{path}: line {lineno} is not badge_id,keyhex")
        bid, k = line.split(",", 1)
        ids.append(int(bid))
        keys.append(bytes.fromhex(k))
    return ids, keys


def build_prefix_table(keys: list[bytes], prefix_keys: int):
    prefix_to_positions = defaultdict(list)
    n = len(keys)
    for i in range(0, n - prefix_keys + 1):
        prefix = b"".join(keys[i:i + prefix_keys])
        prefix_to_positions[prefix].append(i)
    return prefix_to_positions


def build_exact_positions(keys: list[bytes]):
    d = defaultdict(list)
    for i, k in enumerate(keys):
        d[k].append(i)
    return d


def drand48_first_nkeys(seeds: np.ndarray, nkeys: int) -> np.ndarray:
    # returns uint8 array shape (len(seeds), nkeys*10)
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


def drand48_stream(seed32: int, nkeys: int) -> list[bytes]:
    x = ((seed32 & 0xFFFFFFFF) << 16) + 0x330E
    out = []
    for _ in range(nkeys):
        row = bytearray(10)
        for i in range(10):
            x = (A48 * x + C48) & MASK48
            row[i] = (x * 255) >> 48
        out.append(bytes(row))
    return out


def msvcrt_stream(seed32: int, nkeys: int) -> list[bytes]:
    x = seed32 & 0xFFFFFFFF
    out = []
    for _ in range(nkeys):
        row = bytearray(10)
        for i in range(10):
            x = (A31 * x + C31) & MASK31
            r = (x >> 16) & 0x7FFF
            row[i] = (r * 255) >> 15
        out.append(bytes(row))
    return out


def stream_for_seed(model: str, seed32: int, nkeys: int) -> list[bytes]:
    if model == "drand48":
        return drand48_stream(seed32, nkeys)
    if model == "msvcrt":
        return msvcrt_stream(seed32, nkeys)
    raise ValueError(model)


def longest_run_against_file(file_keys: list[bytes], gen_keys: list[bytes], anchor_positions: list[int] | None = None):
    """
    Find the best contiguous exact run between gen_keys and file_keys.
    If anchor_positions is provided, only try file starts in that list.
    """
    n_file = len(file_keys)
    n_gen = len(gen_keys)

    starts = anchor_positions if anchor_positions is not None else range(n_file)

    best = {
        "best_run_len": 0,
        "best_file_start": None,
        "best_gen_start": None,
    }

    # Match only on exact first key, then extend
    exact_pos = build_exact_positions(file_keys)

    for g_start, gk in enumerate(gen_keys):
        if gk not in exact_pos:
            continue
        candidate_file_starts = exact_pos[gk]
        if anchor_positions is not None:
            anchor_set = set(anchor_positions)
            candidate_file_starts = [p for p in candidate_file_starts if p in anchor_set]

        for f_start in candidate_file_starts:
            run = 0
            while (
                g_start + run < n_gen and
                f_start + run < n_file and
                gen_keys[g_start + run] == file_keys[f_start + run]
            ):
                run += 1
            if run > best["best_run_len"]:
                best["best_run_len"] = run
                best["best_file_start"] = f_start
                best["best_gen_start"] = g_start

    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keyfile", required=True)
    ap.add_argument("--model", choices=["drand48", "msvcrt"], default="drand48")
    ap.add_argument("--start-seed32", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--end-seed32", type=lambda x: int(x, 0), default=0xFFFFFFFF)
    ap.add_argument("--chunk", type=int, default=5_000_000)
    ap.add_argument("--prefix-keys", type=int, default=2)
    ap.add_argument("--stream-keys", type=int, default=200)
    ap.add_argument("--top", type=int, default=100)
    ap.add_argument("--report", required=True)
    args = ap.parse_args()

    ids, file_keys = load_keyfile(args.keyfile)
    prefix_table = build_prefix_table(file_keys, args.prefix_keys)

    total_seeds = args.end_seed32 - args.start_seed32 + 1
    total_survivors = 0
    candidates = []

    for s in range(args.start_seed32, args.end_seed32 + 1, args.chunk):
        e = min(s + args.chunk - 1, args.end_seed32)
        seeds = np.arange(s, e + 1, dtype=np.uint64)

        if args.model == "drand48":
            arr = drand48_first_nkeys(seeds, args.prefix_keys)
        else:
            arr = msvcrt_first_nkeys(seeds, args.prefix_keys)

        # Convert only prefix candidates to bytes for set membership
        rows = [bytes(row.tolist()) for row in arr]
        survivor_idx = [i for i, row in enumerate(rows) if row in prefix_table]
        total_survivors += len(survivor_idx)

        for i in survivor_idx:
            seed32 = int(seeds[i] & 0xFFFFFFFF)
            prefix = rows[i]
            positions = prefix_table[prefix]
            candidates.append({
                "seed32": seed32,
                "prefix_hex": prefix.hex(),
                "candidate_file_starts": positions[:32],  # keep bounded
            })

        del seeds, arr, rows, survivor_idx
        gc.collect()

    # Dedup exact seed32/prefix pairs
    seen = set()
    deduped = []
    for c in candidates:
        t = (c["seed32"], c["prefix_hex"])
        if t not in seen:
            seen.add(t)
            deduped.append(c)

    scored = []
    for c in deduped:
        seed32 = c["seed32"]
        gen_keys = stream_for_seed(args.model, seed32, args.stream_keys)
        best = longest_run_against_file(
            file_keys,
            gen_keys,
            anchor_positions=c["candidate_file_starts"]
        )
        scored.append({
            "model": args.model,
            "seed32": seed32,
            "prefix_hex": c["prefix_hex"],
            **best,
        })

    scored.sort(
        key=lambda x: (x["best_run_len"], -(x["best_file_start"] or 10**9)),
        reverse=True
    )

    out = {
        "model": args.model,
        "prefix_keys": args.prefix_keys,
        "stream_keys": args.stream_keys,
        "total_seeds": total_seeds,
        "total_survivors": total_survivors,
        "candidate_count": len(deduped),
        "top": scored[:args.top],
    }

    Path(args.report).write_text(json.dumps(out, indent=2))
    print(f"wrote {args.report}")
    print(f"total_survivors={total_survivors} candidate_count={len(deduped)}")
    print("top seeds:")
    for row in scored[:20]:
        print(row)


if __name__ == "__main__":
    main()
