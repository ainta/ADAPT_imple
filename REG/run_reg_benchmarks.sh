#!/usr/bin/env bash
set -euo pipefail

mkdir -p REG/results

configs=(
  "20 10"
  "40 20"
  "80 40"
)

for cfg in "${configs[@]}"; do
  set -- ${cfg}
  n="$1"
  t="$2"
  for cert in none online full both; do
    raw="REG/results/reg_adapt_${n}_${t}_${cert}.log"
    out="REG/results/reg_adapt_${n}_${t}_${cert}.csv"
    go run REG/main.go "${n}" "${t}" -repeats=30 -cert="${cert}" -local=true > "${raw}"
    awk 'BEGIN{emit=0} /^op,target/{emit=1} emit{print}' "${raw}" > "${out}"
    echo "wrote ${out} and ${raw}"
  done
done
