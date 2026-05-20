# REG-ADAPT artifact and ADAPT/FROST implementation

This fork adds a REG-ADAPT artifact on top of the public ADAPT Go implementation.  REG-ADAPT wraps
ADAPT-style local weighted update routines with:

- epoch state and weight metadata,
- stale-row and owner-bot public-row accounting,
- final and transient exposure checks,
- digest-bound old-epoch transition certificates,
- exact-rank audit mode for GLI derivative rows, and
- benchmark drivers and recorded benchmark outputs.

The REG code lives in:

- `ADAPT/algorithm/reg_guard.go`: guard state, ledger accounting, exact-rank audit, digest-bound
  certification, and wrappers for the ADAPT local update routines.
- `REG/main.go`: benchmark and demo driver.
- `REG/*.sh`: reproduction and summary scripts.
- `REG/results/`: recorded benchmark logs and CSV files.
- `REG/stats/main.go`: mean/median/stddev summary tool.

The original ADAPT/FROST implementation notes are kept below.

## REG-ADAPT quick start

From a fresh checkout:

```bash
git clone https://github.com/ainta/ADAPT_imple.git
cd ADAPT_imple
go mod download
```

Run package-level checks for the ADAPT and REG artifact packages:

```bash
go test ./ADAPT/... ./REG/...
```

The upstream repository has a pre-existing mixed-package layout in `FROST/algorithm`, so
`go test ./...` is not the artifact check used here.

Run one small metadata-only activation benchmark:

```bash
go run REG/main.go 20 10 -repeats=1 -cert=none -local=true
```

Run one digest-bound certificate benchmark:

```bash
go run REG/main.go 20 10 -repeats=1 -cert=online -local=true
```

Run one exact-rank audit benchmark without local ADAPT update cost:

```bash
go run REG/main.go 20 10 -repeats=1 -cert=none -local=false -audit-exact=true
```

Each run prints:

- the ADAPT-style unsafe update-sequence demo, where REG rejects the final unsafe threshold
  decrease;
- the conservative-vs-exact rank tightness demo; and
- a CSV table with guard, certificate, local-update, total, and exact-rank timing columns.

## REG-ADAPT full benchmark reproduction

The full benchmark matrix regenerates `REG/results` tables for `(N,t)=(20,10)`, `(40,20)`, and
`(80,40)` across metadata-only, online-certificate, full-certificate, and diagnostic certificate
modes:

```bash
REG/run_reg_benchmarks.sh
REG/summarize_results.sh
REG/run_reg_audit.sh
go run REG/stats/main.go REG/results/*.csv
```

Outputs:

- raw logs: `REG/results/*.log`
- clean CSV files: `REG/results/*.csv`
- aggregate summaries: `REG/results/summary.txt`, `REG/results/audit_summary.txt`,
  `REG/results/stats.txt`

The benchmark scripts intentionally overwrite files in `REG/results`.  Use a clean clone if you
want to preserve the checked-in results unchanged.

Certificate modes:

- `-cert=none`: conservative metadata guard plus the underlying ADAPT local update.
- `-cert=online`: metadata guard, digest-bound old-epoch sign/verify certificate, and ADAPT local
  update.
- `-cert=full`: nonce preprocessing plus digest-bound old-epoch certificate and ADAPT local update.
- `-cert=both`: diagnostic mode that measures both certificate components in one run; do not use its
  `total_ns` as a deployment total.

Audit options:

- `-audit-exact=true`: compute finite-field ranks for the ledger rows.
- `-audit-point-offset=0`: match the public ADAPT artifact's participant-coordinate convention.
- `-audit-point-offset=1`: use nonzero Shamir points for construction-level audits.

## Env
- Go : 1.21
- Field : edwards 25519 (https://pkg.go.dev/filippo.io/edwards25519)

## Algorithms
- FROST (https://eprint.iacr.org/2020/852)
- ADAPT (ours)

## Usage

Go version >= 1.17 (for edwards 25519 curve lib)

### Package installation (for Curve and Hash)

```bash
git clone https://github.com/hobin-pet/ADAPT
go get -u filippo.io/edwards25519
go get -u golang.org/x/crypto
```

### Package adaptation

```bash
go mod tidy
```

### Execute codes

```bash
# Standard execution with n=100, t=50
go run ADAPT/main.go 100 50
go run FROST/main.go 100 50

# Execute with extreme weight distribution (Alice has most of the weight)
go run ADAPT/main.go 100 50 extreme

# Execute FROST weight virtualization performance test
go run FROST/algorithm/weight_compare_improved.go
```

In the above bash codes:
- The n and t (threshold for FROST and ADAPT) are 100, 50.
- The "extreme" parameter creates an extreme condition where one participant (Alice) holds almost all weight.
- The weight_compare_improved.go file runs tests to analyze FROST performance in virtualization scenarios.

If you want to change the values (n, t), modify the arguments where the first is n and second is t of threshold for FROST and ADAPT, respectively.

The result is total execution time (because the networking is not considered), and it is stored to ADAPT_result.txt and FROST_result.txt when you run `run.sh`

### Result Interpretation

The average result of users is below:

- result / n (when keygen(round1 + round2) and pre-processing of ADAPT, FROST)
- result / t (when sign of FROST)
- result / p (when sign and functionality(WIncrease, TIncrease, WDecrease, TDecrease) of ADAPT)

Where:
- n : # of users of FROST and ADAPT. (In ADAPT case, the sum of weights of users is n, and in FROST case, the weight of each user is just 1.)
- t : # of participants of FROST. (i.e. threshold is t.)
- p : # of participants of ADAPT that configure threshold. (i.e. the sum of weights of participants is t.)

## Comp_Opers Directory: Implementation for comparison of pairing and addition operations

### Env
- Go : 1.21
- Field : BN254 (github.com/consensys/gnark-crypto/ecc/bn254), edwards 25519 

### Usage

Go version >= 1.19 (for gnark-crypto lib)

#### Package installation

```bash
go get github.com/consensys/gnark-crypto/ecc/bn254
```

#### Package adaptation

```bash
go mod tidy
```

#### Execute codes

```bash
go run Comp_Opers/main.go
```

If you run the above command, you can check 10000 times pairing and addition of generator of each curve.
