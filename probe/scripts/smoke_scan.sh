#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-https://example.com}"
OUTPUT_NAME="${2:-smoke_test}"
FORMAT="${3:-json,md,pdf}"

python3 probe.py scan "$TARGET" -o "$OUTPUT_NAME" --format "$FORMAT"

declare -a EXPECTED_EXTS
if [[ "$FORMAT" == "all" ]]; then
  EXPECTED_EXTS=(json md pdf)
else
  IFS=',' read -r -a EXPECTED_EXTS <<< "$FORMAT"
fi

for ext in "${EXPECTED_EXTS[@]}"; do
  ext="$(echo "$ext" | xargs)"
  if [[ -z "$ext" ]]; then
    continue
  fi
  path="scan_results/${OUTPUT_NAME}.${ext}"
  if [[ ! -f "$path" ]]; then
    echo "Missing expected artifact: $path" >&2
    exit 1
  fi
done

echo "Smoke test complete. Artifacts present in scan_results/."
