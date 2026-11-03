#!/usr/bin/env bash
set -euo pipefail

dist_dir="${1:-dist}"
artifact="${dist_dir}/cve_db.sqlite.gz"
manifest="${dist_dir}/manifest.json"
stable_tag="cve-db-latest"
previous_manifest="${PREVIOUS_MANIFEST:-}"

test -f "${artifact}"
test -f "${manifest}"

if [[ -n "${previous_manifest}" && -f "${previous_manifest}" ]]; then
  new_hash="$(python3 -c "import json; print(json.load(open('${manifest}'))['sha256_gz'])")"
  old_hash="$(python3 -c "import json; print(json.load(open('${previous_manifest}'))['sha256_gz'])")"
  if [[ "${new_hash}" == "${old_hash}" ]]; then
    echo "CVE snapshot unchanged; skipping release upload"
    exit 0
  fi
fi

if gh release view "${stable_tag}" >/dev/null 2>&1; then
  gh release upload "${stable_tag}" "${artifact}" "${manifest}" --clobber
else
  gh release create "${stable_tag}" "${artifact}" "${manifest}" \
    --title "Latest CVE database snapshot" \
    --notes "Mutable pointer used by DREAD clients" \
    --latest=false
fi
