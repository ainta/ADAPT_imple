#!/usr/bin/env bash
set -euo pipefail

mkdir -p REG/results

configs=(
  "20 10"
  "40 20"
  "80 40"
)

for cfg in "${configs[@]}"; do
  read -r n t <<< "${cfg}"
  raw="REG/results/reg_adapt_${n}_${t}_audit.log"
  out="REG/results/reg_adapt_${n}_${t}_audit.csv"
  go run REG/main.go "${n}" "${t}" -repeats=30 -cert=none -local=false -audit-exact=true > "${raw}"
  awk 'BEGIN{emit=0} /^op,target/{emit=1} emit{print}' "${raw}" > "${out}"
  echo "wrote ${out} and ${raw}"
done

for f in REG/results/reg_adapt_*_audit.csv; do
  base="$(basename "${f}" .csv)"
  awk -F, -v base="${base}" '
    /^(WIncrease|WDecrease|TIncrease|TDecrease),/ {
      n++
      conservativeFinal += $11
      conservativeTransient += $12
      exactFinal += $18
      exactTransient += $19
      audit += $28
      acc += ($4 == "true")
    }
    END {
      printf "%s rows=%d accepted=%d avg_conservative_final=%.2f avg_exact_final=%.2f avg_conservative_transient=%.2f avg_exact_transient=%.2f avg_exact_audit_us=%.2f\n",
        base, n, acc, conservativeFinal/n, exactFinal/n, conservativeTransient/n, exactTransient/n, audit/n/1000
    }
  ' "${f}"
done
