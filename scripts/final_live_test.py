#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

import requests


def _read_public_key(
    *,
    explicit_b64: str | None,
    explicit_file: str | None,
    registry_base: str,
) -> str:
    if explicit_b64:
        return explicit_b64
    if explicit_file:
        return Path(explicit_file).read_text(encoding="utf-8").strip()
    response = requests.get(f"{registry_base.rstrip('/')}/registry/public-key", timeout=10)
    response.raise_for_status()
    payload = response.json()
    return str(payload["public_key_b64"])


def _check_endpoint(url: str) -> None:
    response = requests.get(url, timeout=10)
    response.raise_for_status()


def _run_verify(
    *,
    continuity_record: Path,
    identity_anchor: Path,
    registry_public_key_b64: str,
) -> tuple[int, str]:
    command = [
        "iap-agent",
        "verify",
        str(continuity_record),
        "--profile",
        "strict",
        "--registry-public-key-b64",
        registry_public_key_b64,
        "--identity-anchor",
        str(identity_anchor),
        "--json",
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    output = (result.stdout + result.stderr).strip()
    return result.returncode, output


def _mutate_signed_field(source: Path, destination: Path) -> None:
    payload = json.loads(source.read_text(encoding="utf-8"))
    if "certificate" in payload and isinstance(payload["certificate"], dict):
        cert = dict(payload["certificate"])
        cert["memory_root"] = "0" * 64
        payload["certificate"] = cert
    else:
        payload["memory_root"] = "0" * 64
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run hardened live-test verification checks."
    )
    parser.add_argument("--registry-base", required=True, help="Base URL for the live registry")
    parser.add_argument(
        "--identity-anchor", required=True, help="Path to identity anchor record JSON"
    )
    parser.add_argument(
        "--continuity-record", required=True, help="Path to continuity record JSON"
    )
    parser.add_argument(
        "--registry-public-key-b64",
        help="Pinned registry public key. If omitted, fetched from /registry/public-key",
    )
    parser.add_argument(
        "--registry-public-key-file",
        help="Read the pinned registry public key from a file instead of CLI text",
    )
    parser.add_argument(
        "--skip-tamper-check",
        action="store_true",
        help="Skip the negative tamper verification check",
    )
    args = parser.parse_args()

    registry_base = args.registry_base.rstrip("/")
    identity_anchor = Path(args.identity_anchor).resolve()
    continuity_record = Path(args.continuity_record).resolve()

    for url in (
        f"{registry_base}/health",
        f"{registry_base}/healthz",
        f"{registry_base}/registry/public-key",
    ):
        _check_endpoint(url)

    registry_public_key_b64 = _read_public_key(
        explicit_b64=args.registry_public_key_b64,
        explicit_file=args.registry_public_key_file,
        registry_base=registry_base,
    )

    code, output = _run_verify(
        continuity_record=continuity_record,
        identity_anchor=identity_anchor,
        registry_public_key_b64=registry_public_key_b64,
    )
    if code != 0:
        raise SystemExit(f"valid chain verification failed:\n{output}")

    print("valid_chain_ok=true")

    if args.skip_tamper_check:
        print("tamper_check_skipped=true")
        return 0

    with tempfile.TemporaryDirectory(prefix="iap-live-test-") as tmpdir:
        tampered = Path(tmpdir) / "tampered_continuity_record.json"
        _mutate_signed_field(continuity_record, tampered)
        tamper_code, tamper_output = _run_verify(
            continuity_record=tampered,
            identity_anchor=identity_anchor,
            registry_public_key_b64=registry_public_key_b64,
        )
        if tamper_code == 0:
            raise SystemExit("tamper check failed: mutated record still verified successfully")
        print("tamper_detection_ok=true")
        print(f"tamper_verify_output={tamper_output}")

    print("health_checks_ok=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
