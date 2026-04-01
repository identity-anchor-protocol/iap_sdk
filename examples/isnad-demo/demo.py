#!/usr/bin/env python3
"""Offline Isnad demo: record actions, mint receipts, and detect tampering."""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import os
import sys
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from iap_sdk.actions import (  # noqa: E402
    IAPOperator,
    action_event_hash,
    canonical_action_receipt_bytes,
    default_actions_dir,
    flush_action_receipts,
    summarize_action_chain,
    verify_action_chain,
)
from iap_sdk.certificates import PROTOCOL_VERSION  # noqa: E402
from iap_sdk.cli.main import main as cli_main  # noqa: E402


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


@dataclass
class DemoResult:
    verify_before_ok: bool
    verify_after_receipts_ok: bool
    verify_after_tamper_ok: bool
    action_count: int
    receipt_count: int
    latest_sequence: int | None
    latest_receipt_sequence: int | None
    workdir: str


class _FakeRegistryClient:
    def __init__(self) -> None:
        private = Ed25519PrivateKey.generate()
        self._private_key = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        self.public_key_b64 = _b64(
            private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        self.latest_receipt: dict | None = None

    def get_latest_action_receipt(self, agent_id: str) -> dict:
        if self.latest_receipt is None:
            return {
                "agent_id": agent_id,
                "latest_sequence": None,
                "latest_event_hash": None,
                "latest_receipt": None,
            }
        return {
            "agent_id": agent_id,
            "latest_sequence": self.latest_receipt["sequence"],
            "latest_event_hash": self.latest_receipt["event_hash"],
            "latest_receipt": self.latest_receipt,
        }

    def submit_action_receipt(self, payload: dict) -> dict:
        event = payload["event"]
        receipt = {
            "receipt_id": f"receipt-{event['sequence']}",
            "agent_id": event["agent_id"],
            "sequence": event["sequence"],
            "prev_event_hash": event["prev_event_hash"],
            "event_hash": action_event_hash(event),
            "context_root": event["context_root"],
            "timestamp_utc": event["timestamp_utc"],
            "server_timestamp_utc": "2026-04-01T00:00:00Z",
            "action_kind": event["action_kind"],
            "fork_detected": False,
            "conflicting_event_hashes": [],
            "registry_id": "demo-registry",
            "protocol_version": PROTOCOL_VERSION,
        }
        signature = Ed25519PrivateKey.from_private_bytes(self._private_key).sign(
            canonical_action_receipt_bytes(receipt)
        )
        receipt["registry_signature_b64"] = _b64(signature)
        self.latest_receipt = receipt
        return receipt


class _DemoHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Demo", "ok")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def _set_memory_root(project_root: Path, memory_root: str) -> None:
    state_root_path = project_root / ".iap" / "state" / "state_root.json"
    payload = json.loads(state_root_path.read_text(encoding="utf-8"))
    payload["memory_root"] = memory_root
    state_root_path.write_text(
        json.dumps(payload, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _tamper_receipt(actions_dir: Path) -> None:
    receipts_path = actions_dir / "receipts.log"
    lines = receipts_path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[-1])
    payload["context_root"] = "f" * 64
    lines[-1] = json.dumps(payload, sort_keys=True)
    receipts_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_demo(workdir: Path) -> DemoResult:
    workdir.mkdir(parents=True, exist_ok=True)

    init_out = []
    with _pushd(workdir):
        rc = cli_main(
            ["init", "--project-local", "--json"],
            stdout=_ListWriter(init_out),
            stderr=sys.stderr,
        )
    if rc != 0:
        raise RuntimeError("failed to initialize project-local identity")
    init_payload = json.loads("".join(init_out))
    _set_memory_root(workdir, "a" * 64)

    operator = IAPOperator.from_project(project_root=workdir)

    print("Step 1/5: local identity ready")
    print(f"agent_id={init_payload['agent_id']}")

    print("Step 2/5: actions recorded")
    operator.mkdir(workdir / "memory")
    operator.file_write(workdir / "memory" / "note.txt", "hello isnad")
    operator.run_shell(
        sys.executable,
        ["-c", "print('shell action ok')"],
        cwd=workdir,
    )

    server = ThreadingHTTPServer(("127.0.0.1", 0), _DemoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        operator.http_request(
            "POST",
            f"http://127.0.0.1:{server.server_port}/demo",
            headers={"X-Demo": "trace"},
            body='{"demo":true}',
            header_allowlist=["X-Demo"],
            response_header_allowlist=["X-Demo", "Content-Type"],
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    actions_dir = default_actions_dir(workdir)
    summary_before = summarize_action_chain(actions_dir)
    verify_before = verify_action_chain(
        actions_dir,
        expected_agent_id=init_payload["agent_id"],
    )
    print(f"action_count={summary_before.event_count}")
    print(f"verify_before_ok={verify_before.ok}")

    print("Step 3/5: offline receipts minted")
    registry = _FakeRegistryClient()
    flush_result = flush_action_receipts(
        actions_dir,
        client=registry,
        agent_public_key_b64=init_payload["public_key_b64"],
        registry_public_key_b64=registry.public_key_b64,
    )
    verify_after_receipts = verify_action_chain(
        actions_dir,
        expected_agent_id=init_payload["agent_id"],
        registry_public_key_b64=registry.public_key_b64,
    )
    print(f"receipt_count={flush_result.submitted_count}")
    print(f"verify_after_receipts_ok={verify_after_receipts.ok}")

    print("Step 4/5: receipt history silently modified")
    _tamper_receipt(actions_dir)
    print("tamper=receipts.log last context_root overwritten")

    print("Step 5/5: receipt verification fails")
    verify_after_tamper = verify_action_chain(
        actions_dir,
        expected_agent_id=init_payload["agent_id"],
        registry_public_key_b64=registry.public_key_b64,
    )
    print(f"verify_after_tamper_ok={verify_after_tamper.ok}")
    print(f"verify_after_tamper_reason={verify_after_tamper.reason}")

    summary_after = summarize_action_chain(actions_dir)
    return DemoResult(
        verify_before_ok=verify_before.ok,
        verify_after_receipts_ok=verify_after_receipts.ok,
        verify_after_tamper_ok=verify_after_tamper.ok,
        action_count=summary_after.event_count,
        receipt_count=summary_after.receipt_count,
        latest_sequence=summary_after.latest_sequence,
        latest_receipt_sequence=summary_after.latest_receipt_sequence,
        workdir=str(workdir),
    )


class _ListWriter:
    def __init__(self, parts: list[str]) -> None:
        self._parts = parts

    def write(self, value: str) -> int:
        self._parts.append(value)
        return len(value)

    def flush(self) -> None:
        return


@contextlib.contextmanager
def _pushd(path: Path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the offline Isnad action provenance demo.")
    parser.add_argument(
        "--workdir",
        default="./isnad-demo-output",
        help="Output directory for demo artifacts",
    )
    args = parser.parse_args()
    result = run_demo(Path(args.workdir).resolve())
    return 0 if not result.verify_after_tamper_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
