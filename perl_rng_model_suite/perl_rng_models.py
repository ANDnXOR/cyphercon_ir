from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Tuple
from pathlib import Path
from collections import defaultdict
import json

MASK48 = (1 << 48) - 1
A48 = 0x5DEECE66D
C48 = 0xB


def load_keyfile(path: str | Path) -> tuple[list[int], list[bytes], dict[bytes, list[int]]]:
    ids: list[int] = []
    keys: list[bytes] = []
    positions_by_key: dict[bytes, list[int]] = defaultdict(list)
    p = Path(path)
    for lineno, raw in enumerate(p.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if ',' not in line:
            raise ValueError(f"{p}: line {lineno} is not 'badge_id,keyhex': {line!r}")
        bid_s, keyhex = line.split(',', 1)
        bid = int(bid_s)
        key = bytes.fromhex(keyhex)
        if len(key) != 10:
            raise ValueError(f"{p}: line {lineno} key is not 10 bytes: {keyhex!r}")
        positions_by_key[key].append(len(keys))
        ids.append(bid)
        keys.append(key)
    return ids, keys, positions_by_key


def drand48_key(seed32: int, warmup_draws: int = 0, nbytes: int = 10) -> bytes:
    x = ((seed32 & 0xFFFFFFFF) << 16) + 0x330E
    for _ in range(warmup_draws):
        x = (A48 * x + C48) & MASK48
    out = bytearray(nbytes)
    for i in range(nbytes):
        x = (A48 * x + C48) & MASK48
        out[i] = (x * 255) >> 48
    return bytes(out)


def msvcrt_rand_key(seed32: int, warmup_draws: int = 0, nbytes: int = 10) -> bytes:
    x = seed32 & 0xFFFFFFFF
    for _ in range(warmup_draws):
        x = (214013 * x + 2531011) & 0x7FFFFFFF
    out = bytearray(nbytes)
    for i in range(nbytes):
        x = (214013 * x + 2531011) & 0x7FFFFFFF
        r = (x >> 16) & 0x7FFF
        out[i] = (r * 255) >> 15
    return bytes(out)


MODEL_FUNCS: dict[str, Callable[[int, int, int], bytes]] = {
    # Historically plausible Perl RNG families to test.
    # pre-5.20 Windows Perl generally delegated to CRT rand().
    'msvcrt_pre520': msvcrt_rand_key,
    # 5.20+ Perl switched to internal drand48-ish generator.
    'drand48_520_plus': drand48_key,
}


def key_hex_from_model(model: str, seed32: int, warmup_draws: int = 0) -> str:
    return MODEL_FUNCS[model](seed32, warmup_draws=warmup_draws).hex()


def dedup_hits_by_seed32(hits: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for h in hits:
        t = (h['model'], h['seed32'], h['warmup_draws'], h['file_pos'], h['key_hex'])
        if t not in seen:
            seen.add(t)
            out.append(h)
    return out


def save_json(path: str | Path, obj) -> None:
    Path(path).write_text(json.dumps(obj, indent=2, sort_keys=False))
