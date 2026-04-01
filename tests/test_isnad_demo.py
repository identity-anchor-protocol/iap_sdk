from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_demo_module():
    module_path = Path(__file__).resolve().parents[1] / "examples" / "isnad-demo" / "demo.py"
    spec = importlib.util.spec_from_file_location("isnad_demo", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load isnad demo module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_isnad_demo_detects_receipt_tamper(tmp_path: Path) -> None:
    module = _load_demo_module()
    workdir = tmp_path / "isnad-demo"
    result = module.run_demo(workdir)

    assert result.verify_before_ok is True
    assert result.verify_after_receipts_ok is True
    assert result.verify_after_tamper_ok is False
    assert result.action_count == 4
    assert result.receipt_count == 4
    assert result.latest_sequence == 4
    assert result.latest_receipt_sequence == 4
    assert (workdir / ".iap" / "actions" / "receipts.log").exists()
