# Session Map Exact Keygen Package

This package contains a standalone generator that takes a `complete_session_map_v1.json`
file and regenerates the exact mapped keys under the current best-fit model:

- RNG core: `drand48`
- seed: direct `seed32`
- warmup draws: `0`
- per-badge skip: `0`

## Files

- `generate_exact_keys_from_session_map.py` — standalone generator
- `README.md` — this file

## Usage

```bash
python3 generate_exact_keys_from_session_map.py \
  --session-map-json complete_session_map_v1.json \
  --report exact_session_keygen_summary.json \
  --keys-json exact_session_keys.json \
  --keys-csv exact_session_keys.csv
```

## Outputs

- `exact_session_keygen_summary.json` — summary metadata
- `exact_session_keys.json` — all generated keys with segment metadata
- `exact_session_keys.csv` — CSV export of the same keys

## Notes

- This script expects the session map JSON to contain a top-level `segments` array.
- It generates keys in file order for every listed segment.
- Full map count should be 524 generated keys for the current `complete_session_map_v1.json`.
