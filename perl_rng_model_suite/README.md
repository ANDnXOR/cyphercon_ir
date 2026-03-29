# Perl RNG model suite for Cyphercon badge-key analysis

This suite is for testing historically plausible Perl RNG/key-generation models against the published `Tymkrs_Cyphercon_2020_keys.txt` file and then scoring the resulting exact-hit anchors in file order.

It includes:

- `perl_rng_models.py` — shared models and key-file loader
- `compare_models.py` — exact-hit search across plausible Perl RNG families
- `score_runs.py` — score contiguous file-order runs around exact-hit anchors
- `expand_hits_with_skip.py` — expand promising anchors across auto-discovered islands with skip-in-whole-keys
- `tests/test_models.py` — regression tests

## Historically plausible models implemented

- `drand48_520_plus` — Perl 5.20+ internal drand48-style RNG with 32-bit seed init
- `msvcrt_pre520` — pre-5.20 Windows Perl delegating to CRT `rand()`-style 15-bit output

## 1) Run regression tests

```bash
python3 -m unittest tests.test_models
```

## 2) Search exact hits across models

Canonical 32-bit sweep (drand48 and msvcrt, no warmup):

```bash
python3 compare_models.py \
  --keyfile /path/to/Tymkrs_Cyphercon_2020_keys.txt \
  --models drand48_520_plus msvcrt_pre520 \
  --start-seed32 0 \
  --end-seed32 0xffffffff \
  --chunk 5000000 \
  --warmup-min 0 \
  --warmup-max 0 \
  --report exact_hits.json
```

Search small warmup range too:

```bash
python3 compare_models.py \
  --keyfile /path/to/Tymkrs_Cyphercon_2020_keys.txt \
  --models drand48_520_plus msvcrt_pre520 \
  --start-seed32 0 \
  --end-seed32 0xffffffff \
  --warmup-min 0 \
  --warmup-max 32 \
  --report exact_hits_warmup.json
```

## 3) Score exact-hit anchors in file order

```bash
python3 score_runs.py \
  --keyfile /path/to/Tymkrs_Cyphercon_2020_keys.txt \
  --hits-json exact_hits.json \
  --radius 12 \
  --report scored_runs.json
```

Inspect anchors with high:
- `forward_longest_contig`
- `forward_exact`

## 4) Expand promising anchors across islands with key skips

```bash
python3 expand_hits_with_skip.py \
  --keyfile /path/to/Tymkrs_Cyphercon_2020_keys.txt \
  --scored-hits-json scored_runs.json \
  --skip-keys-min 0 \
  --skip-keys-max 500 \
  --top-anchors 100 \
  --top-per-island 25 \
  --report expanded_hits.json
```

This stage is intended to answer:
- does a hit become a stronger local session explanation with a small whole-key offset?
- do duplicate/reflash clusters or ascending runs line up with a candidate seed?

## Notes

- The programmer script shows `int(rand(255))`, so all models generate 10 bytes in `0x00..0xFE`.
- Searching beyond one 32-bit cycle adds no information for the drand48-style model implemented here.
- `expand_hits_with_skip.py` uses **whole-key skips** (`10` draws per key), because the flashing script itself does not call `rand()` between bytes of a single key.
