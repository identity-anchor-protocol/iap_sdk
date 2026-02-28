from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_demo_module():
    module_path = Path(__file__).resolve().parents[1] / "examples" / "state-drift-demo" / "demo.py"
    spec = importlib.util.spec_from_file_location("state_drift_demo", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load state drift demo module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_state_drift_demo_detects_tamper(tmp_path: Path) -> None:
    module = _load_demo_module()
    workdir = tmp_path / "state-drift"
    result = module.run_demo(workdir)
    assert result == 0
    assert (workdir / "anchor_record.json").exists()
