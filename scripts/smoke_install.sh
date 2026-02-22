#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${ROOT_DIR}/.venv-smoke"

rm -rf "${VENV_DIR}"
python3 -m venv "${VENV_DIR}"
source "${VENV_DIR}/bin/activate"

python -m pip install -U pip
python -m pip install -e "${ROOT_DIR}[dev]"

iap-agent version
iap-agent version --json

deactivate
echo "smoke install passed"
