"""Test environment normalization for the monorepo SDK suite."""

from __future__ import annotations

import os
import site
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AMCS_PATH = REPO_ROOT / "AMCS-0.1"
USER_SITE = Path(site.getusersitepackages())

if str(AMCS_PATH) not in sys.path:
    sys.path.insert(0, str(AMCS_PATH))
if USER_SITE.exists() and str(USER_SITE) not in sys.path:
    sys.path.insert(0, str(USER_SITE))

pythonpath_entries = [str(AMCS_PATH)]
if USER_SITE.exists():
    pythonpath_entries.append(str(USER_SITE))
existing_pythonpath = os.environ.get("PYTHONPATH")
if existing_pythonpath:
    pythonpath_entries.append(existing_pythonpath)
os.environ["PYTHONPATH"] = os.pathsep.join(pythonpath_entries)

_TEST_HOME = tempfile.mkdtemp(prefix="iap-sdk-tests-home-")
os.environ["HOME"] = _TEST_HOME

for env_var in ("IAP_REGISTRY_BASE", "IAP_REGISTRY_API_KEY", "IAP_ACCOUNT_TOKEN"):
    os.environ.pop(env_var, None)
