#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DREAD_PY="${REPO_ROOT}/dread.py"
VENV_DIR="${REPO_ROOT}/.venv"
ENV_FILE="${REPO_ROOT}/.env"
ENV_EXAMPLE="${REPO_ROOT}/.env.example"

OS_NAME="$(uname -s)"

if [[ -z "${INSTALL_BIN_DIR:-}" ]]; then
  if [[ "${OS_NAME}" == "Darwin" ]]; then
    INSTALL_BIN_DIR="/usr/local/bin"
  elif [[ "${OS_NAME}" == "Linux" ]]; then
    if [[ ":${PATH}:" == *":/usr/local/bin:"* ]]; then
      INSTALL_BIN_DIR="/usr/local/bin"
    else
      INSTALL_BIN_DIR="/usr/bin"
    fi
  else
    INSTALL_BIN_DIR="/usr/local/bin"
  fi
fi

INSTALL_BIN_PATH="${INSTALL_BIN_DIR}/dread"

SHELL_NAME="$(basename "${SHELL:-}")"
RC_FILE=""
ASN_NEEDS_UPDATE=0
CVE_NEEDS_BOOTSTRAP=0

print_before_first_scan_notice() {
  local y b d r
  y='\033[1;33m'
  b='\033[33m'
  d='\033[2m'
  r='\033[0m'
  if [[ ! -t 1 ]] || [[ -n "${NO_COLOR:-}" ]]; then
    y=''
    b=''
    d=''
    r=''
  fi

  echo ""
  echo -e "${y}========================================================================${r}"
  echo -e "${y}  Before your first scan (required — installer does not download CVE data)${r}"
  echo -e "${y}========================================================================${r}"
  echo ""

  if [[ "${CVE_NEEDS_BOOTSTRAP}" -eq 1 ]]; then
    echo -e "${y}  CVE database is missing or incomplete. Run the steps below before scanning.${r}"
    echo ""
  elif [[ "${ASN_NEEDS_UPDATE}" -eq 1 ]]; then
    echo -e "${b}  ASN data should be refreshed. CVE steps still apply if you have not bootstrapped yet.${r}"
    echo ""
  else
    echo -e "${b}  Local databases look populated; you can still refresh before scanning.${r}"
    echo ""
  fi

  if [[ "${ASN_NEEDS_UPDATE}" -eq 1 ]]; then
    echo -e "${y}  1) dread update-db${r}"
  else
    echo -e "${b}  1) dread update-db${r}  ${d}(ASN ok — optional refresh)${r}"
  fi

  echo -e "${b}  2) export NVD_API_KEY=\"your-nvd-api-key\"${r}  ${d}(optional, faster incremental sync)${r}"

  if [[ "${CVE_NEEDS_BOOTSTRAP}" -eq 1 ]]; then
    echo -e "${y}  3) dread update-cve-db${r}  ${d}(recommended; skipping may delay the first scan)${r}"
  else
    echo -e "${b}  3) dread update-cve-db${r}  ${d}(CVE loaded — incremental refresh)${r}"
  fi

  echo -e "${b}  4) dread cve-stats${r}"
  echo -e "${y}  5) dread scan example.com${r}"
  echo ""
  echo -e "${y}========================================================================${r}"
}

if [[ "${SHELL_NAME}" == "zsh" ]]; then
  RC_FILE="${HOME}/.zshrc"
elif [[ "${SHELL_NAME}" == "bash" ]]; then
  if [[ "${OS_NAME}" == "Darwin" ]]; then
    RC_FILE="${HOME}/.bash_profile"
  else
    RC_FILE="${HOME}/.bashrc"
  fi
fi

echo "[*] DREAD installer"
echo "[*] Repo root: ${REPO_ROOT}"

if [[ ! -f "${DREAD_PY}" ]]; then
  echo "[!] Could not find dread.py at ${DREAD_PY}" >&2
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  if [[ -f "${ENV_EXAMPLE}" ]]; then
    cp "${ENV_EXAMPLE}" "${ENV_FILE}"
    echo "[+] Created .env from .env.example"
  else
    cat > "${ENV_FILE}" <<'EOF'
EOF
    echo "[+] Created .env template"
  fi
else
  echo "[=] .env already exists"
fi

if [[ ! -d "${VENV_DIR}" ]]; then
  python3 -m venv "${VENV_DIR}"
  echo "[+] Created virtual environment at ${VENV_DIR}"
else
  echo "[=] Virtual environment already exists"
fi

VENV_PY="${VENV_DIR}/bin/python"
if [[ ! -x "${VENV_PY}" ]]; then
  if [[ -x "${VENV_DIR}/bin/python3" ]]; then
    VENV_PY="${VENV_DIR}/bin/python3"
    echo "[=] Using ${VENV_PY}"
  else
    echo "[!] Virtualenv interpreter missing; recreating ${VENV_DIR}"
    rm -rf "${VENV_DIR}"
    python3 -m venv "${VENV_DIR}"
    VENV_PY="${VENV_DIR}/bin/python"
    if [[ ! -x "${VENV_PY}" && -x "${VENV_DIR}/bin/python3" ]]; then
      VENV_PY="${VENV_DIR}/bin/python3"
    fi
  fi
fi

if [[ ! -x "${VENV_PY}" ]]; then
  echo "[!] Virtualenv python missing after recreation: ${VENV_PY}" >&2
  exit 1
fi

if [[ -f "${REPO_ROOT}/requirements.txt" ]]; then
  "${VENV_PY}" -m pip install --upgrade pip
  "${VENV_PY}" -m pip install -r "${REPO_ROOT}/requirements.txt"
  echo "[+] Installed requirements.txt into venv"
else
  echo "[!] requirements.txt not found in ${REPO_ROOT}" >&2
  exit 1
fi

if [[ -f "${REPO_ROOT}/requirements-dev.txt" ]]; then
  "${VENV_PY}" -m pip install -r "${REPO_ROOT}/requirements-dev.txt"
  echo "[+] Installed requirements-dev.txt (test tooling) into venv"
fi

# Optional browser-backed DOM XSS / screenshot checks. Kept separate because it
# downloads a browser; skip with DREAD_SKIP_DOM=1, and a failure here never
# fails the install (the checks degrade gracefully when playwright is absent).
DOM_REQS="${REPO_ROOT}/requirements-dom.txt"
if [[ "${DREAD_SKIP_DOM:-0}" == "1" ]]; then
  echo "[=] Skipping DOM check dependencies (DREAD_SKIP_DOM=1)"
elif [[ -f "${DOM_REQS}" ]]; then
  echo "[*] Installing optional DOM check dependencies (playwright + chromium)..."
  if "${VENV_PY}" -m pip install -r "${DOM_REQS}" && "${VENV_PY}" -m playwright install chromium; then
    echo "[+] Installed DOM check dependencies (playwright + chromium)"
  else
    echo "[!] DOM check dependencies did not install; DOM XSS and screenshot checks will be skipped."
    echo "[!] Retry: ${VENV_PY} -m pip install -r ${DOM_REQS} && ${VENV_PY} -m playwright install chromium"
  fi
fi

# Web GUI dashboard build (needs Node/npm). Skip with DREAD_SKIP_DASHBOARD=1;
# non-fatal so a missing Node toolchain never fails the install.
DASHBOARD_DIR="${REPO_ROOT}/reports/dashboard"
if [[ "${DREAD_SKIP_DASHBOARD:-0}" == "1" ]]; then
  echo "[=] Skipping web GUI dashboard build (DREAD_SKIP_DASHBOARD=1)"
elif [[ -f "${DASHBOARD_DIR}/package.json" ]]; then
  if command -v npm >/dev/null 2>&1; then
    echo "[*] Building the web GUI dashboard (npm)..."
    if (cd "${DASHBOARD_DIR}" && npm install && npm run build); then
      echo "[+] Built the web GUI dashboard"
    else
      echo "[!] Dashboard build failed; the web GUI stays unavailable until you build it."
      echo "[!] Retry: (cd ${DASHBOARD_DIR} && npm install && npm run build)"
    fi
  else
    echo "[!] npm not found; skipped the web GUI dashboard build."
    echo "[!] Install Node.js, then: (cd ${DASHBOARD_DIR} && npm install && npm run build)"
  fi
fi

echo ""
echo "[*] ASN database (local status, no network):"
"${VENV_PY}" -c "
import os
import sys
sys.path.insert(0, '${REPO_ROOT}/probe')
from scanner.asn_db_updater import ASN_DB_PATH, describe_asn_db_local_status

status = describe_asn_db_local_status()
tty = sys.stdout.isatty() and not os.environ.get('NO_COLOR', '').strip()
print(f'    File: {ASN_DB_PATH}')
if 'missing' in status or 'outdated' in status:
    if tty:
        print(f'    Status: \\033[1;31m{status}\\033[0m')
        print('    \\033[33mRun: dread update-db\\033[0m')
    else:
        print(f'    Status: {status}')
        print('    Run: dread update-db')
else:
    if tty:
        print(f'    Status: \\033[1;32m{status}\\033[0m')
    else:
        print(f'    Status: {status}')
"

echo ""
echo "[*] CVE database (local status, no network):"
CVE_NEEDS_BOOTSTRAP=1
set +e
"${VENV_PY}" -c "
import os
import sys
sys.path.insert(0, '${REPO_ROOT}/probe')
from scanner.cve_db_manager import CVE_DB_PATH, describe_cve_db_local_status

status = describe_cve_db_local_status()
ready = status.startswith('ok (') and 'CVEs loaded)' in status
tty = sys.stdout.isatty() and not os.environ.get('NO_COLOR', '').strip()
print(f'    File: {CVE_DB_PATH}')
if ready:
    if tty:
        print(f'    Status: \\033[1;32m{status}\\033[0m')
    else:
        print(f'    Status: {status}')
else:
    if tty:
        print(f'    Status: \\033[1;31m{status}\\033[0m')
        print('    \\033[33mRun: dread update-cve-db\\033[0m')
    else:
        print(f'    Status: {status}')
        print('    Run: dread update-cve-db')
sys.exit(0 if ready else 1)
"
cve_ready_rc=$?
set -e
if [[ "${cve_ready_rc}" -eq 0 ]]; then
  CVE_NEEDS_BOOTSTRAP=0
fi

ASN_NEEDS_UPDATE=0
if "${VENV_PY}" -c "
import sys
sys.path.insert(0, '${REPO_ROOT}/probe')
from scanner.asn_db_updater import describe_asn_db_local_status
s = describe_asn_db_local_status()
raise SystemExit(0 if ('missing' in s or 'outdated' in s) else 1)
" 2>/dev/null; then
  ASN_NEEDS_UPDATE=1
fi

LAUNCHER_TMP="$(mktemp)"
cat > "${LAUNCHER_TMP}" <<EOF
#!/usr/bin/env bash
set -euo pipefail

DREAD_REPO="${REPO_ROOT}"
VENV_PY="\${DREAD_REPO}/.venv/bin/python"
DREAD_PY="\${DREAD_REPO}/dread.py"
ENV_FILE="\${DREAD_REPO}/.env"

if [[ ! -x "\${VENV_PY}" && -x "\${DREAD_REPO}/.venv/bin/python3" ]]; then
  VENV_PY="\${DREAD_REPO}/.venv/bin/python3"
fi

if [[ -f "\${ENV_FILE}" ]]; then
  set -a
  source "\${ENV_FILE}"
  set +a
fi

exec "\${VENV_PY}" "\${DREAD_PY}" "\$@"
EOF
chmod +x "${LAUNCHER_TMP}"

mkdir -p "${INSTALL_BIN_DIR}" 2>/dev/null || true
if install -m 0755 "${LAUNCHER_TMP}" "${INSTALL_BIN_PATH}" 2>/dev/null; then
  echo "[+] Installed launcher to ${INSTALL_BIN_PATH}"
else
  echo "[!] Could not write ${INSTALL_BIN_PATH} without elevated permissions."
  echo "[*] Retrying with sudo..."
  sudo mkdir -p "${INSTALL_BIN_DIR}"
  sudo install -m 0755 "${LAUNCHER_TMP}" "${INSTALL_BIN_PATH}"
  echo "[+] Installed launcher to ${INSTALL_BIN_PATH} (sudo)"
fi
rm -f "${LAUNCHER_TMP}"

# A shell alias named `dread` (e.g. left over from an older version of
# this installer, or copied in via synced dotfiles from another machine)
# shadows the real launcher in interactive shells even though this script
# -- running under bash -- has no visibility into zsh/fish alias tables to
# detect that itself. Scrub it from the rc file we're about to manage so
# "install completed" actually means the command works.
#
# Only delete a line if it's PROVABLY just a standalone `alias dread=...`
# declaration -- the whole line, nothing else. A line sharing `; other-cmd`,
# `&& other-cmd`, a leading conditional, or a trailing `\` continuation gets
# left alone; deleting the whole line would silently destroy that unrelated
# content too. Those get reported for manual cleanup instead.
DREAD_ALIAS_RE='alias[[:space:]]+dread='
DREAD_ALIAS_STANDALONE_RE='^[[:space:]]*alias[[:space:]]+dread=("[^"]*"|'"'"'[^'"'"']*'"'"'|[^[:space:];&|\\]+)[[:space:]]*$'
if [[ -n "${RC_FILE}" ]] && [[ -f "${RC_FILE}" ]] && grep -qE "${DREAD_ALIAS_RE}" "${RC_FILE}"; then
  if grep -qE "${DREAD_ALIAS_STANDALONE_RE}" "${RC_FILE}"; then
    echo "[!] Found an existing 'dread' alias in ${RC_FILE} that would shadow the installed launcher."
    if [[ "${OS_NAME}" == "Darwin" ]]; then
      sed -i '' -E "/${DREAD_ALIAS_STANDALONE_RE}/d" "${RC_FILE}"
    else
      sed -i -E "/${DREAD_ALIAS_STANDALONE_RE}/d" "${RC_FILE}"
    fi
    echo "[+] Removed stale dread alias from ${RC_FILE}"
  fi
  if grep -qE "${DREAD_ALIAS_RE}" "${RC_FILE}"; then
    echo "[!] ${RC_FILE} still defines a 'dread' alias on a compound, conditional, or continued line -- it may shadow the installed launcher. Please remove it manually."
  fi
fi

if [[ "${OS_NAME}" == "Darwin" ]] && [[ "${INSTALL_BIN_PATH}" == *"/sbin/"* ]]; then
  MAC_BIN="/usr/local/bin/dread"
  if [[ ! -f "${MAC_BIN}" ]] || [[ "${INSTALL_BIN_PATH}" -nt "${MAC_BIN}" ]] 2>/dev/null; then
    if install -m 0755 "${INSTALL_BIN_PATH}" "${MAC_BIN}" 2>/dev/null; then
      echo "[+] Also installed launcher to ${MAC_BIN} (macOS PATH compatibility)"
    else
      echo "[*] Could not copy to ${MAC_BIN} without elevated permissions; retrying with sudo..."
      sudo install -m 0755 "${INSTALL_BIN_PATH}" "${MAC_BIN}"
      echo "[+] Also installed launcher to ${MAC_BIN} (sudo)"
    fi
  fi
fi

if ! command -v dread >/dev/null 2>&1; then
  ALT_BIN=""
  if [[ "${OS_NAME}" == "Linux" ]]; then
    if [[ "${INSTALL_BIN_DIR}" != "/usr/local/bin" ]]; then
      ALT_BIN="/usr/local/bin/dread"
    fi
  elif [[ "${OS_NAME}" == "Darwin" ]]; then
    if [[ "${INSTALL_BIN_DIR}" != "/usr/local/bin" ]]; then
      ALT_BIN="/usr/local/bin/dread"
    fi
  fi

  if [[ -n "${ALT_BIN}" ]]; then
    if install -m 0755 "${INSTALL_BIN_PATH}" "${ALT_BIN}" 2>/dev/null; then
      echo "[+] Copied launcher to ${ALT_BIN}"
    else
      echo "[*] Could not copy to ${ALT_BIN} without elevated permissions."
      echo "[*] Retrying with sudo..."
      sudo install -m 0755 "${INSTALL_BIN_PATH}" "${ALT_BIN}"
      echo "[+] Copied launcher to ${ALT_BIN} (sudo)"
    fi
    INSTALL_BIN_PATH="${ALT_BIN}"
  fi

  if [[ -n "${RC_FILE}" ]]; then
    if [[ ":${PATH}:" != *":${INSTALL_BIN_DIR}:"* ]]; then
      if ! grep -F "export PATH=\"${INSTALL_BIN_DIR}:\$PATH\"" "${RC_FILE}" >/dev/null 2>&1; then
        {
          echo ""
          echo "export PATH=\"${INSTALL_BIN_DIR}:\$PATH\""
        } >> "${RC_FILE}"
        echo "[+] Added ${INSTALL_BIN_DIR} to PATH in ${RC_FILE}"
      else
        echo "[=] PATH export already present in ${RC_FILE}"
      fi
    fi
  elif [[ "${SHELL_NAME}" == "fish" ]]; then
    echo "[*] fish shell detected."
    echo "[*] Add once (universal): set -U fish_user_paths ${INSTALL_BIN_DIR} \$fish_user_paths"
  else
    echo "[*] Unknown shell '${SHELL_NAME:-unknown}'."
    echo "[*] Ensure ${INSTALL_BIN_DIR} is in your PATH."
  fi
fi

echo ""
echo "[✓] Install complete"
print_before_first_scan_notice
if [[ -n "${RC_FILE}" ]]; then
  echo "[*] If command is still not found: source ${RC_FILE} && hash -r"
elif [[ "${SHELL_NAME}" == "fish" ]]; then
  echo "[*] If command is still not found: run the fish_user_paths command above, then open a new shell."
else
  echo "[*] If command is still not found: refresh your shell and ensure ${INSTALL_BIN_DIR} is on PATH."
fi
