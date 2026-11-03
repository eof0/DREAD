#!/usr/bin/env bash
set -euo pipefail

gh release list --limit 500 --json tagName -q '.[].tagName' | while read -r tag; do
  if [[ "${tag}" =~ ^cve-db-[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    echo "Deleting dated release ${tag}"
    if ! gh release delete "${tag}" -y --cleanup-tag 2>/dev/null; then
      gh release delete "${tag}" -y
    fi
  fi
done
