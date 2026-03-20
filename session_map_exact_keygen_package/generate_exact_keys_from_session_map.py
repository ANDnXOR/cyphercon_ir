#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

MASK48 = (1 << 48) - 1
A48 = 0x5DEECE66D
C48 = 0xB


def drand48_key_at_index(seed32: int, key_index: int) -> bytes:
    x = ((seed32 & 0xFFFFFFFF) << 16) + 0x330E
    for _ in range(key_index * 10):
        x = (A48 * x + C48) & MASK48
    row = bytearray(10)
    for i in range(10):
        x = (A48 * x + C48) & MASK48
        row[i] = (x * 255) >> 48
    return bytes(row)


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate exact recovered keys from a complete session map JSON.")
    ap.add_argument("--session-map-json", required=True, help="Path to complete_session_map_v1.json")
    ap.add_argument("--report", required=True, help="Path to summary JSON output")
    ap.add_argument("--keys-json", required=True, help="Path to generated keys JSON output")
    ap.add_argument("--keys-csv", required=True, help="Path to generated keys CSV output")
    args = ap.parse_args()

    obj = json.loads(Path(args.session_map_json).read_text())
    segments = sorted(obj["segments"], key=lambda s: s["file_start"])

    keys = []
    for seg in segments:
        seed32 = int(seg["seed32"])
        file_start = int(seg["file_start"])
        run_len = int(seg["length"])
        for i in range(run_len):
            key_hex = drand48_key_at_index(seed32, i).hex()
            keys.append({
                "label": seg["label"],
                "kind": seg["kind"],
                "seed32": seed32,
                "session_file_start": file_start,
                "session_file_end": int(seg["file_end"]),
                "session_run_len": run_len,
                "badge_id_at_start": seg.get("badge_id_at_start"),
                "notes": seg.get("notes", ""),
                "file_pos": file_start + i,
                "key_index": i,
                "key_hex": key_hex,
            })

    summary = {
        "model": {
            "rng_core": "drand48",
            "seed": "direct seed32",
            "warmup_draws": 0,
            "per_badge_skip": 0,
        },
        "segment_count": len(segments),
        "generated_key_count": len(keys),
        "labels": [s["label"] for s in segments],
    }

    Path(args.report).write_text(json.dumps(summary, indent=2))
    Path(args.keys_json).write_text(json.dumps(keys, indent=2))

    fieldnames = [
        "label", "kind", "seed32", "session_file_start", "session_file_end",
        "session_run_len", "badge_id_at_start", "notes", "file_pos",
        "key_index", "key_hex"
    ]
    with open(args.keys_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in keys:
            w.writerow(row)

    print(f"wrote {args.report}")
    print(f"wrote {args.keys_json}")
    print(f"wrote {args.keys_csv}")
    print(f"generated_key_count={len(keys)}")


if __name__ == "__main__":
    main()
