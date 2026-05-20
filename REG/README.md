# REG-ADAPT wrapper benchmark

This directory instantiates a rank-exposure guard wrapper around the public ADAPT Go artifact.

## Files

- `../ADAPT/algorithm/reg_guard.go`: REG state, exposure ledger, final/transient checks, digest-bound state certification, exact-rank audit mode, silent ADAPT local-operation runners, and certificate timing hooks.
- `main.go`: benchmark driver.
- `run_reg_benchmarks.sh`: runs the benchmark matrix and writes raw logs plus clean CSV files.
- `run_reg_audit.sh`: runs exact-rank audit measurements without local ADAPT update cost.
- `summarize_results.sh`: summarizes the clean CSV files.
- `stats/main.go`: reports mean, median, and standard deviation for benchmark columns.

## Modes

- `-cert=none`: metadata guard plus the underlying ADAPT local update.
- `-cert=online`: metadata guard, digest-bound old-epoch sign/verify certificate, and ADAPT local update.
- `-cert=full`: metadata guard, nonce preprocessing plus digest-bound old-epoch sign/verify certificate, and ADAPT local update.
- `-cert=both`: diagnostic mode that measures both certificate components in one run; do not use its `total_ns` as a deployment total.
- `-audit-exact=true`: compute finite-field ranks for the GLI derivative rows represented by the ledger, alongside the conservative row-count envelope.
- `-audit-point-offset=0`: use the same participant-coordinate convention as the public ADAPT artifact. Use `1` for nonzero Shamir points in construction-level audits.
- `-sequence=true`: run the listed operations against one evolving REG state. The default benchmarks each operation from a fresh state.

Certificate modes use the REG state's certifier set as the actual temporary ADAPT signing set for
the digest-bound transition certificate. The transition digest binds the pre-state digest, post-state
digest, operation, target, delta, certifier-set digest, and certifier weight. The transition-level
verifier checks the message, aggregate signature, old-epoch public key, certifier set, and certifier
weight before activation. The original ADAPT `thresholdSet` is restored before local update
benchmarking.

## Reproduce

Quick smoke checks:

```bash
go test ./ADAPT/... ./REG/...
go run REG/main.go 20 10 -repeats=1 -cert=none -local=true
go run REG/main.go 20 10 -repeats=1 -cert=online -local=true
go run REG/main.go 20 10 -repeats=1 -cert=none -local=false -audit-exact=true
```

Full benchmark reproduction:

```bash
REG/run_reg_benchmarks.sh
REG/summarize_results.sh
REG/run_reg_audit.sh
go run REG/stats/main.go REG/results/*.csv
```

The raw `.log` files include the ADAPT package initialization output and the reachable-state
rejection demo. The `.csv` files contain only the machine-readable benchmark table.
The full benchmark scripts overwrite files under `REG/results`; use a clean clone to preserve the
checked-in result files unchanged.
