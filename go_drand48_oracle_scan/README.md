
# Go drand48 Oracle Scan

This is the faster CPU-native version of the greenfield scanner.

It assumes:
- `drand48`
- captured `0x03`
- captured `0x04`
- dump `ONCE`
- optional badge ID hint
- optional requested-credits hint

## Why this is faster

Compared with the Python scanner, this version adds:

- Go native code
- CPU parallel workers
- stage-1 pruning on `0x03` only:
  - dump ONCE must match
  - optional badge ID must match
  - optional requested credits must match
  - checksum must be valid

Only surviving keys pay the `0x04` decrypt cost.

## Build

```bash
go build -o drand48_oracle_scan main.go
```

## Usage

Known-good single seed:

```bash
./drand48_oracle_scan   --type3-hex 536d6173683f000302ff758f477dd59482a8c5bbe6   --type4-hex 536d6173683f030401b576460019673a1704f8750a   --dump-once-hex 6ca3   --badge-id 0x01b5   --requested-credits 0x0001   --seed32s 4245513479
```

Narrowed range:

```bash
./drand48_oracle_scan   --type3-hex 536d6173683f000302ff758f477dd59482a8c5bbe6   --type4-hex 536d6173683f030401b576460019673a1704f8750a   --dump-once-hex 6ca3   --badge-id 0x01b5   --requested-credits 0x0001   --start-seed32 0xFC000000   --end-seed32 0xFFFFFFFF   --keys-per-seed 18   --workers 8
```

## Notes

The default `keys-per-seed` is 100 because the recovered range-map analysis showed a max single-seed interval of 100 keys.
You can lower it for experiments or raise it if you want a more conservative sweep.
