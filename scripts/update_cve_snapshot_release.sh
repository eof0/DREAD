#!/usr/bin/env bash
set -euo pipefail

dist_dir="${1:-dist}"
artifact="${dist_dir}/cve_db.sqlite.gz"
manifest="${dist_dir}/manifest.json"
dated_tag="cve-db-$(date -u +%Y-%m-%d)"
stable_tag="cve-db-latest"

test -f "${artifact}"
test -f "${manifest}"

if ! gh release view "${dated_tag}" >/dev/null 2>&1; then
  gh release create "${dated_tag}" "${artifact}" "${manifest}" \
    --title "CVE DB snapshot ${dated_tag}" \
    --notes "Automated daily CVE database snapshot" \
    --latest=false
fi

if gh release view "${stable_tag}" >/dev/null 2>&1; then
  gh release upload "${stable_tag}" "${artifact}" "${manifest}" --clobber
else
  gh release create "${stable_tag}" "${artifact}" "${manifest}" \
    --title "Latest CVE database snapshot" \
    --notes "Mutable pointer used by DREAD clients" \
    --latest=false
fi
