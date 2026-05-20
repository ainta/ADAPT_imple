#!/usr/bin/env bash
set -euo pipefail

for mode in none online full; do
  echo "mode=${mode}"
  for f in REG/results/reg_adapt_*_"${mode}".csv; do
    base="$(basename "${f}" .csv)"
    awk -F, -v base="${base}" '
      /^(WIncrease|WDecrease|TIncrease|TDecrease),/ {
        n++
        meta += $20
        con += $21
        cfull += $22
        local += $26
        total += $27
        audit += $28
        acc += ($4 == "true")
      }
      END {
        printf "%s rows=%d accepted=%d avg_metadata_us=%.2f avg_cert_online_ms=%.3f avg_cert_full_ms=%.3f avg_local_ms=%.3f avg_total_ms=%.3f avg_exact_audit_us=%.2f\n",
          base, n, acc, meta/n/1000, con/n/1000000, cfull/n/1000000, local/n/1000000, total/n/1000000, audit/n/1000
      }
    ' "${f}"
  done
done
