<p align="center">
  <img src="https://res.cloudinary.com/noqoikpl/image/upload/v1789009052/dread.png" alt="DREAD logo" width="220" />
</p>

<p align="center">
  <a href="https://github.com/eof0/DREAD/actions/workflows/ci.yml"><img src="https://github.com/eof0/DREAD/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
  <img src="https://img.shields.io/badge/python-3.12%2B-blue.svg" alt="Python 3.12+" />
  <img src="https://img.shields.io/badge/engine-Rust-orange.svg" alt="Rust engine" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg" alt="Platform: Linux | macOS" />
</p>

# DREAD

DREAD is a CLI-first security assessment suite. The public build focuses on two production-ready capabilities:

- external attack-surface discovery
- web-focused vulnerability scanning

It is built to run cleanly in local shells, CI pipelines, and Docker.
Supported hosts are Linux and macOS.
> Use only on systems you own or are explicitly authorized to test.

## Current Product Status

| Product | Purpose | Status |
|---|---|---|
| `dread` | Suite orchestrator and unified CLI | Implemented |
| `scope` | Subdomain/cloud/IP discovery | Implemented |
| `probe` | Crawl + plugin-based vulnerability scanning | Implemented |
| `reports` | Aggregated suite reporting | Implemented |
| `dreadai` | Verification helpers | Implemented (expanding) |
| `watch`, `graph`, `intel`, `spear`, `cannon` | Planned suite modules | Scaffold |

Live registry:

```bash
python dread.py products
python dread.py products --json
```

## Quick Start

### Option 1 (recommended): installer

```bash
./install.sh

# first load after install (if needed)
# zsh:  source ~/.zshrc && hash -r
# bash: source ~/.bashrc && hash -r   (or ~/.bash_profile on macOS)
# fish: set -U fish_user_paths /usr/local/bin $fish_user_paths

# verify
dread --help
```

### After install (before your first scan)

Refresh local intelligence databases once so scans are useful. This is separate from `install.sh` (the installer may remind you about ASN data but does not download CVE data).

```bash
# 1) ASN database (fast; needed for ASN/IP intel plugins)
dread update-db

# 2) CVE database: verified snapshot, then incremental NVD catch-up
dread update-cve-db

# Check what was loaded
dread cve-stats

# 3) Run your first assessment
dread scan example.com
```

**Ongoing maintenance:**

```bash
dread update-db              # refresh ASN data when stale
dread update-cve-db          # snapshot if needed, otherwise incremental sync
```

If you skip this step, the first scan uses the same snapshot bootstrap automatically. See [CVE database](#cve-database) for direct-NVD and offline fallback behavior.

### Option 2: manual setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Same post-install DB steps as Option 1 (use python dread.py if dread is not on PATH)
python dread.py update-db
python dread.py update-cve-db
python dread.py cve-stats

# Full workflow (default): Scope discovery -> Probe scan
python dread.py scan example.com

# Discovery only
python dread.py recon example.com

# scanner-only (Probe path)
python dread.py hunt https://example.com
# equivalent
python dread.py probe scan https://example.com
```

### Important behavior

- `scan` = default full suite workflow
- `recon` = discovery only (Scope); `hunt` = Probe-only scan
- `full-scan`, `discover`, and `light-scan` still work as hidden compatibility aliases
- apex and `www` are treated as same site during crawl scope
- redundant `www.<apex>` follow-on targets are avoided in suite scans

### Web application

Run the local application to launch scans and view reports, history, findings, and dashboards:

```bash
python -m reports.api
```

Open `http://127.0.0.1:8765`.
Runs are stored in `~/.dread/runs` by default.
Set `DREAD_RUNS_DIR` to use another directory.

## Installer details

The installer:

- creates or reuses `.env`
- creates/repairs `.venv`
- installs runtime dependencies from `requirements.txt`
- installs a launcher in an OS-appropriate bin directory
- prints local ASN DB status and suggests `dread update-db` if stale

It does **not** download or build the CVE database. Follow [After install (before your first scan)](#after-install-before-your-first-scan) before relying on CVE correlation in scan results.

## Docker

Portable CLI usage without local Python dependency:

```bash
docker build -t dread .
docker run --rm dread --help
docker run --rm dread scan example.com
```

Persist artifacts to host:

```bash
mkdir -p ./dread-out
docker run --rm -v "$(pwd)/dread-out:/out" dread scan example.com --suite-out /out
```

Compose path:

```bash
docker compose build
docker compose run --rm dread --help
docker compose run --rm dread scan example.com
```

## Data Maintenance Commands

### ASN database

```bash
python dread.py update-db          # alias: update-asn-db
```

### CVE database

Probe stores mutable CVE data in `~/.dread/data/cve_db.sqlite` and matches CVEs by detected product and version. Set `DREAD_DATA_DIR` to use a different data directory.

| Phase | What happens |
|---|---|
| **Bootstrap** | Downloads and verifies the published full-corpus snapshot |
| **Incremental sync** | Fetches only NVD records modified since the last cursor (fast) |
| **Scan** | Fingerprints the target, then queries the DB for that product/CPE |

The default command installs a verified snapshot when the database is missing or incomplete, then fetches changes made after the snapshot cursor:

```bash
python dread.py update-cve-db

# Install the snapshot without an incremental NVD catch-up
python dread.py update-cve-db --snapshot-only

# Inspect local coverage and counts
python dread.py cve-stats
```

Direct-NVD modes skip the snapshot. DREAD splits long NVD date ranges into 119-day windows:

```bash
# Rebuild the complete corpus directly from NVD
python dread.py update-cve-db --full

# Raw unfiltered crawl (best-effort offset resumption)
python dread.py update-cve-db --raw-full

# Build partial publication-window databases
python dread.py update-cve-db --days 30
python dread.py update-cve-db --years 15

# Synchronize directly without downloading a snapshot
python dread.py update-cve-db --no-snapshot

# Skip automatic CVE refresh at scan startup
export DREAD_SKIP_CVE_UPDATE=1
```

Set `NVD_API_KEY` for the higher NVD request limit. Interrupted windowed updates resume from the last committed page. DREAD checksum-verifies snapshots and installs them atomically. If the snapshot is unavailable on an empty installation, it falls back to a 30-day publication database and warns that coverage is partial.

Direct product commands are also available via `python probe/probe.py ...` with the same flags.

### Other maintenance

```bash
python dread.py profiles

# Bounded active web vulnerability checks
python dread.py scan https://example.com --profile safe-active
```

## Suite Output and Reporting

Full run with aggregated artifacts:

```bash
python dread.py scan example.com \
  --suite-out ./suite_runs \
  --suite-report \
  --suite-verify
```

Report formats:

- Probe: `json`, `md`, `pdf`, `html`
- Scope: `json`, `yaml`, `table`

Note on public HTML output: the `.html` artifact is a placeholder page in this public repository; use JSON/Markdown/PDF for report content.

## Development

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest
```

## Roadmap

Short term: complete and integrate scaffold modules (`watch`, `graph`, `intel`, `spear`, `cannon`).

Implementation direction: Python remains the orchestration core; performance-sensitive components move into compiled tooling (Go/Rust/Zig).

## License

- MIT (`LICENSE`)
