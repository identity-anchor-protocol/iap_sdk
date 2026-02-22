"""Command-line interface for iap-agent."""

from __future__ import annotations

import argparse
import json
import sys
import time
import webbrowser
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import Sequence

from iap_sdk.certificates import PROTOCOL_VERSION
from iap_sdk.cli.amcs import AMCSError, get_amcs_root
from iap_sdk.cli.config import CLIConfig, ConfigError, load_cli_config
from iap_sdk.cli.identity import IdentityError, load_identity, load_or_create_identity
from iap_sdk.cli.sessions import SessionError, save_session_record
from iap_sdk.client import RegistryClient
from iap_sdk.errors import RegistryUnavailableError
from iap_sdk.manifest import build_identity_manifest
from iap_sdk.requests import build_continuity_request, sign_continuity_request
from iap_sdk.verify import verify_certificate_file


def _sdk_version() -> str:
    try:
        return pkg_version("iap-sdk")
    except PackageNotFoundError:
        return "0.0.0+local"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iap-agent")
    parser.add_argument(
        "--config",
        default=None,
        help="Path to CLI config TOML (default: ~/.iap_agent/config.toml)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    version = sub.add_parser("version", help="Show CLI and protocol version")
    version.add_argument("--json", action="store_true", help="Print version details as JSON")

    init = sub.add_parser("init", help="Initialize or load local agent identity")
    init.add_argument(
        "--identity-file",
        default=None,
        help="Path to local identity file (default: ~/.iap_agent/identity/ed25519.json)",
    )
    init.add_argument(
        "--show-public",
        action="store_true",
        help="Print only public fields (agent_id + public_key_b64)",
    )
    init.add_argument("--json", action="store_true", help="Print identity details as JSON")
    verify = sub.add_parser("verify", help="Verify certificate offline")
    verify.add_argument("certificate_json")
    verify.add_argument("--registry-public-key-b64", default=None)
    verify.add_argument("--registry-base", default=None)
    verify.add_argument("--identity-anchor", default=None)
    verify.add_argument("--profile", choices=("basic", "strict"), default="basic")
    verify.add_argument("--previous-certificate", default=None)
    verify.add_argument("--witness-bundle", default=None, help="Path to JSON witness bundle list")
    verify.add_argument("--min-witnesses", type=int, default=0)
    verify.add_argument("--json", action="store_true")

    amcs = sub.add_parser("amcs", help="Local AMCS operations")
    amcs_sub = amcs.add_subparsers(dest="amcs_command", required=True)
    amcs_root = amcs_sub.add_parser("root", help="Read memory root and sequence from local AMCS DB")
    amcs_root.add_argument("--amcs-db", default=None, help="Path to local AMCS SQLite DB")
    amcs_root.add_argument("--agent-id", default=None, help="Agent id to query in AMCS")
    amcs_root.add_argument(
        "--identity-file",
        default=None,
        help="Path to local identity file when deriving agent_id fallback",
    )
    amcs_root.add_argument("--json", action="store_true", help="Print AMCS root details as JSON")

    anchor = sub.add_parser("anchor", help="Identity-anchor operations")
    anchor_sub = anchor.add_subparsers(dest="anchor_command", required=True)
    anchor_issue = anchor_sub.add_parser("issue", help="Issue identity anchor certificate")
    anchor_issue.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    anchor_issue.add_argument(
        "--identity-file",
        default=None,
        help="Path to local identity file (default: ~/.iap_agent/identity/ed25519.json)",
    )
    anchor_issue.add_argument(
        "--agent-name",
        default="Local Agent",
        help="Optional agent display name metadata",
    )
    anchor_issue.add_argument("--json", action="store_true", help="Print response as JSON")

    continuity = sub.add_parser("continuity", help="Continuity operations")
    continuity_sub = continuity.add_subparsers(dest="continuity_command", required=True)
    continuity_request = continuity_sub.add_parser(
        "request", help="Submit signed continuity request"
    )
    continuity_request.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    continuity_request.add_argument(
        "--identity-file",
        default=None,
        help="Path to local identity file (default: ~/.iap_agent/identity/ed25519.json)",
    )
    continuity_request.add_argument("--agent-name", default="Local Agent")
    continuity_request.add_argument("--agent-custody-class", default=None)
    continuity_request.add_argument("--memory-root", default=None)
    continuity_request.add_argument("--sequence", type=int, default=None)
    continuity_request.add_argument("--amcs-db", default=None, help="Path to local AMCS SQLite DB")
    continuity_request.add_argument(
        "--sessions-dir",
        default=None,
        help="Directory to store request session artifacts (default from config)",
    )
    continuity_request.add_argument("--json", action="store_true", help="Print response as JSON")
    continuity_pay = continuity_sub.add_parser("pay", help="Show payment instructions for request")
    continuity_pay.add_argument("--request-id", required=True)
    continuity_pay.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    continuity_pay.add_argument("--success-url", default=None)
    continuity_pay.add_argument("--cancel-url", default=None)
    continuity_pay.add_argument("--open-browser", action="store_true")
    continuity_pay.add_argument("--json", action="store_true", help="Print payment details as JSON")
    continuity_wait = continuity_sub.add_parser("wait", help="Wait until request is CERTIFIED")
    continuity_wait.add_argument("--request-id", required=True)
    continuity_wait.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    continuity_wait.add_argument("--timeout-seconds", type=int, default=300)
    continuity_wait.add_argument("--poll-seconds", type=int, default=5)
    continuity_wait.add_argument("--json", action="store_true")

    continuity_cert = continuity_sub.add_parser("cert", help="Fetch and save issued certificate")
    continuity_cert.add_argument("--request-id", required=True)
    continuity_cert.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    continuity_cert.add_argument(
        "--output-file",
        default=None,
        help=(
            "Path for certificate bundle JSON "
            "(default: <sessions_dir>/certificates/<request_id>.json)"
        ),
    )
    continuity_cert.add_argument("--json", action="store_true")

    flow = sub.add_parser("flow", help="High-level guided flows")
    flow_sub = flow.add_subparsers(dest="flow_command", required=True)
    flow_run = flow_sub.add_parser("run", help="Run full end-to-end flow")
    flow_run.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    flow_run.add_argument(
        "--identity-file",
        default=None,
        help="Path to local identity file (default: ~/.iap_agent/identity/ed25519.json)",
    )
    flow_run.add_argument(
        "--agent-name",
        default="Local Agent",
        help="Optional agent display name metadata",
    )
    flow_run.add_argument("--agent-custody-class", default=None)
    flow_run.add_argument("--amcs-db", default=None, help="Path to local AMCS SQLite DB")
    flow_run.add_argument("--memory-root", default=None)
    flow_run.add_argument("--sequence", type=int, default=None)
    flow_run.add_argument("--request-timeout-seconds", type=int, default=300)
    flow_run.add_argument("--poll-seconds", type=int, default=5)
    flow_run.add_argument("--open-browser", action="store_true")
    flow_run.add_argument(
        "--output-dir",
        default=None,
        help="Directory for flow artifacts (default: <sessions_dir>/flows/<request_id>)",
    )
    flow_run.add_argument("--json", action="store_true")

    return parser


def _emit_beta_warning(config: CLIConfig, command: str, stderr) -> None:
    if command == "version":
        return
    if not config.beta_mode:
        return
    print(
        "[beta] iap-agent is in beta mode; commands and outputs may change.",
        file=stderr,
    )


def _run_version(*, config: CLIConfig, as_json: bool, stdout) -> int:
    payload = {
        "cli": "iap-agent",
        "sdk_version": _sdk_version(),
        "protocol_version": PROTOCOL_VERSION,
        "maturity_level": config.maturity_level,
        "beta_mode": config.beta_mode,
        "default_registry_base": config.registry_base,
    }
    if as_json:
        print(json.dumps(payload, sort_keys=True), file=stdout)
    else:
        beta_mode_str = str(payload["beta_mode"]).lower()
        print(f"iap-agent {payload['sdk_version']}", file=stdout)
        print(f"protocol: {payload['protocol_version']}", file=stdout)
        print(
            f"maturity: {payload['maturity_level']} (beta_mode={beta_mode_str})",
            file=stdout,
        )
        print(f"default registry: {payload['default_registry_base']}", file=stdout)
    return 0


def _coming_soon(*, path: str, stdout) -> int:
    print(f"{path}: coming soon", file=stdout)
    return 2


def _run_init(*, args, stdout, stderr) -> int:
    try:
        identity, created, identity_path = load_or_create_identity(args.identity_file)
    except IdentityError as exc:
        print(f"identity error: {exc}", file=stderr)
        return 1

    payload = {
        "identity_path": str(identity_path),
        "created": created,
        "agent_id": identity.agent_id,
        "public_key_b64": identity.public_key_b64,
    }
    if not args.show_public:
        payload["private_key_b64"] = identity.private_key_b64

    if args.json:
        print(json.dumps(payload, sort_keys=True), file=stdout)
        return 0

    print(f"identity_path: {payload['identity_path']}", file=stdout)
    print(f"created: {str(payload['created']).lower()}", file=stdout)
    print(f"agent_id: {payload['agent_id']}", file=stdout)
    print(f"public_key_b64: {payload['public_key_b64']}", file=stdout)
    if not args.show_public:
        print("private_key_b64: [hidden in non-json output]", file=stdout)
    return 0


def _run_amcs_root(*, args, config: CLIConfig, stdout, stderr) -> int:
    amcs_db_path = args.amcs_db or config.amcs_db_path

    agent_id = args.agent_id
    if not agent_id:
        try:
            identity, _ = load_identity(args.identity_file)
            agent_id = identity.agent_id
        except IdentityError as exc:
            print(f"identity error: {exc}", file=stderr)
            return 1

    try:
        result = get_amcs_root(amcs_db_path=amcs_db_path, agent_id=agent_id)
    except AMCSError as exc:
        print(f"amcs error: {exc}", file=stderr)
        return 1

    payload = {
        "agent_id": result.agent_id,
        "amcs_db_path": result.amcs_db_path,
        "memory_root": result.memory_root,
        "sequence": result.sequence,
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True), file=stdout)
        return 0

    print(f"agent_id: {payload['agent_id']}", file=stdout)
    print(f"amcs_db_path: {payload['amcs_db_path']}", file=stdout)
    print(f"sequence: {payload['sequence']}", file=stdout)
    print(f"memory_root: {payload['memory_root']}", file=stdout)
    return 0


def _run_anchor_issue(*, args, config: CLIConfig, stdout, stderr) -> int:
    try:
        identity, _ = load_identity(args.identity_file)
    except IdentityError as exc:
        print(f"identity error: {exc}", file=stderr)
        return 1

    registry_base = args.registry_base or config.registry_base
    client = RegistryClient(base_url=registry_base)
    payload = {
        "agent_public_key_b64": identity.public_key_b64,
        "agent_id": identity.agent_id,
        "metadata": {"agent_name": args.agent_name},
    }

    try:
        response = client.submit_identity_anchor(payload)
        already_exists = False
    except RegistryUnavailableError as exc:
        message = str(exc)
        if "409" in message and "already" in message.lower():
            response = {
                "status": "already-exists",
                "agent_id": identity.agent_id,
                "registry_base": registry_base,
            }
            already_exists = True
        else:
            print(f"registry error: {exc}", file=stderr)
            return 2

    output = {
        "registry_base": registry_base,
        "agent_id": identity.agent_id,
        "already_exists": already_exists,
        "certificate": response,
    }
    if args.json:
        print(json.dumps(output, sort_keys=True), file=stdout)
        return 0

    print(f"registry_base: {registry_base}", file=stdout)
    print(f"agent_id: {identity.agent_id}", file=stdout)
    print(f"already_exists: {str(already_exists).lower()}", file=stdout)
    print(f"certificate_type: {response.get('certificate_type', 'n/a')}", file=stdout)
    return 0


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _run_continuity_request(*, args, config: CLIConfig, stdout, stderr) -> int:
    try:
        identity, _ = load_identity(args.identity_file)
    except IdentityError as exc:
        print(f"identity error: {exc}", file=stderr)
        return 1

    memory_root = args.memory_root
    sequence = args.sequence
    if memory_root is None or sequence is None:
        amcs_db_path = args.amcs_db or config.amcs_db_path
        try:
            amcs = get_amcs_root(amcs_db_path=amcs_db_path, agent_id=identity.agent_id)
        except AMCSError as exc:
            print(f"amcs error: {exc}", file=stderr)
            return 1
        if memory_root is None:
            memory_root = amcs.memory_root
        if sequence is None:
            sequence = amcs.sequence

    manifest = build_identity_manifest(
        {
            "AGENT.md": f"{args.agent_name}\n",
            "SOUL.md": "Purpose: continuity certification via iap-agent CLI\n",
        }
    )

    payload = build_continuity_request(
        agent_public_key_b64=identity.public_key_b64,
        agent_id=identity.agent_id,
        agent_name=args.agent_name,
        agent_custody_class=args.agent_custody_class,
        memory_root=memory_root,
        sequence=sequence,
        manifest_version=manifest["manifest_version"],
        manifest_hash=manifest["manifest_hash"],
    )
    signed_payload = sign_continuity_request(payload, identity.private_key_bytes)

    registry_base = args.registry_base or config.registry_base
    client = RegistryClient(base_url=registry_base)
    try:
        response = client.submit_continuity_request(signed_payload)
    except RegistryUnavailableError as exc:
        print(f"registry error: {exc}", file=stderr)
        return 2

    request_id = response.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        print("registry error: invalid response (missing request_id)", file=stderr)
        return 2

    session_payload = {
        "created_at": _utc_now_iso(),
        "registry_base": registry_base,
        "agent_id": identity.agent_id,
        "request_id": request_id,
        "request_payload": signed_payload,
        "response": response,
    }
    sessions_dir = args.sessions_dir or config.sessions_dir
    try:
        session_path = save_session_record(
            sessions_dir=sessions_dir,
            request_id=request_id,
            payload=session_payload,
        )
    except SessionError as exc:
        print(f"session error: {exc}", file=stderr)
        return 1

    output = {
        "request_id": request_id,
        "status": response.get("status"),
        "agent_id": identity.agent_id,
        "memory_root": memory_root,
        "sequence": sequence,
        "session_file": str(session_path),
        "registry_base": registry_base,
        "payment": {
            "lnbits_payment_hash": response.get("lnbits_payment_hash"),
            "lightning_invoice": response.get("lightning_invoice"),
            "amount_sats": response.get("amount_sats"),
        },
    }
    if args.json:
        print(json.dumps(output, sort_keys=True), file=stdout)
        return 0

    print(f"request_id: {output['request_id']}", file=stdout)
    print(f"status: {output['status']}", file=stdout)
    print(f"agent_id: {output['agent_id']}", file=stdout)
    print(f"memory_root: {output['memory_root']}", file=stdout)
    print(f"sequence: {output['sequence']}", file=stdout)
    print(f"session_file: {output['session_file']}", file=stdout)
    print(f"registry_base: {output['registry_base']}", file=stdout)
    return 0


def _run_continuity_pay(*, args, config: CLIConfig, stdout, stderr) -> int:
    registry_base = args.registry_base or config.registry_base
    client = RegistryClient(base_url=registry_base)

    stripe_session = None
    try:
        stripe_session = client.create_stripe_checkout_session(
            request_id=args.request_id,
            success_url=args.success_url,
            cancel_url=args.cancel_url,
        )
    except RegistryUnavailableError:
        stripe_session = None

    if stripe_session is not None:
        checkout_url = stripe_session.get("checkout_url")
        output = {
            "request_id": args.request_id,
            "registry_base": registry_base,
            "payment_method": "stripe",
            "session_id": stripe_session.get("session_id"),
            "checkout_url": checkout_url,
            "payment_status": stripe_session.get("payment_status"),
        }
        if args.open_browser and isinstance(checkout_url, str):
            try:
                webbrowser.open(checkout_url, new=2)
            except Exception:  # pragma: no cover
                pass
        if args.json:
            print(json.dumps(output, sort_keys=True), file=stdout)
            return 0
        print(f"payment_method: {output['payment_method']}", file=stdout)
        print(f"request_id: {output['request_id']}", file=stdout)
        print(f"checkout_url: {output['checkout_url']}", file=stdout)
        print(f"session_id: {output['session_id']}", file=stdout)
        return 0

    try:
        status = client.get_continuity_status(args.request_id)
    except RegistryUnavailableError as exc:
        print(f"registry error: {exc}", file=stderr)
        return 2

    output = {
        "request_id": args.request_id,
        "registry_base": registry_base,
        "payment_method": "lnbits",
        "status": status.get("status"),
        "lnbits_payment_hash": status.get("lnbits_payment_hash"),
        "lightning_invoice": status.get("lightning_invoice"),
    }
    if args.json:
        print(json.dumps(output, sort_keys=True), file=stdout)
        return 0

    print(f"payment_method: {output['payment_method']}", file=stdout)
    print(f"request_id: {output['request_id']}", file=stdout)
    print(f"status: {output['status']}", file=stdout)
    print(f"lnbits_payment_hash: {output['lnbits_payment_hash']}", file=stdout)
    print(f"lightning_invoice: {output['lightning_invoice']}", file=stdout)
    return 0


def _run_continuity_wait(*, args, config: CLIConfig, stdout, stderr) -> int:
    registry_base = args.registry_base or config.registry_base
    timeout_seconds = max(1, int(args.timeout_seconds))
    poll_seconds = max(1, int(args.poll_seconds))
    client = RegistryClient(base_url=registry_base)

    deadline = time.time() + timeout_seconds
    latest = None
    while time.time() < deadline:
        try:
            latest = client.get_continuity_status(args.request_id)
        except RegistryUnavailableError as exc:
            print(f"registry error: {exc}", file=stderr)
            return 2
        status = latest.get("status")
        if status == "CERTIFIED":
            break
        time.sleep(poll_seconds)

    if not latest or latest.get("status") != "CERTIFIED":
        print("timeout waiting for CERTIFIED status", file=stderr)
        return 3

    output = {
        "request_id": args.request_id,
        "registry_base": registry_base,
        "status": latest.get("status"),
        "paid_at": latest.get("paid_at"),
    }
    if args.json:
        print(json.dumps(output, sort_keys=True), file=stdout)
        return 0
    print(f"request_id: {output['request_id']}", file=stdout)
    print(f"status: {output['status']}", file=stdout)
    print(f"paid_at: {output['paid_at']}", file=stdout)
    return 0


def _run_continuity_cert(*, args, config: CLIConfig, stdout, stderr) -> int:
    registry_base = args.registry_base or config.registry_base
    client = RegistryClient(base_url=registry_base)
    try:
        bundle = client.get_continuity_certificate(args.request_id)
    except RegistryUnavailableError as exc:
        print(f"registry error: {exc}", file=stderr)
        return 2

    if args.output_file:
        output_path = Path(args.output_file)
    else:
        output_path = Path(config.sessions_dir) / "certificates" / f"{args.request_id}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bundle, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    output = {
        "request_id": args.request_id,
        "registry_base": registry_base,
        "output_file": str(output_path),
        "certificate_type": (bundle.get("certificate") or {}).get("certificate_type"),
    }
    if args.json:
        print(json.dumps(output, sort_keys=True), file=stdout)
        return 0
    print(f"request_id: {output['request_id']}", file=stdout)
    print(f"certificate_type: {output['certificate_type']}", file=stdout)
    print(f"output_file: {output['output_file']}", file=stdout)
    return 0


def _run_verify(*, args, config: CLIConfig, stdout, stderr) -> int:
    registry_public_key_b64 = args.registry_public_key_b64
    if registry_public_key_b64 is None:
        registry_base = args.registry_base or config.registry_base
        client = RegistryClient(base_url=registry_base)
        try:
            key_payload = client.get_public_registry_key()
        except RegistryUnavailableError as exc:
            print(f"registry error: {exc}", file=stderr)
            return 2
        registry_public_key_b64 = key_payload.get("public_key_b64")
        if not isinstance(registry_public_key_b64, str) or not registry_public_key_b64:
            print("registry error: missing public_key_b64 in registry response", file=stderr)
            return 2

    witnesses = None
    if args.witness_bundle:
        try:
            witnesses = json.loads(Path(args.witness_bundle).read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"verify error: invalid witness bundle: {exc}", file=stderr)
            return 1

    ok, reason = verify_certificate_file(
        args.certificate_json,
        registry_public_key_b64=registry_public_key_b64,
        profile=args.profile,
        identity_anchor_path=args.identity_anchor,
        previous_certificate_path=args.previous_certificate,
        witness_bundle=witnesses,
        min_witnesses=args.min_witnesses,
    )
    if args.json:
        print(json.dumps({"ok": ok, "reason": reason}, sort_keys=True), file=stdout)
    else:
        print(reason, file=stdout)
    return 0 if ok else 4


def _print_step(stdout, *, index: int, total: int, title: str) -> None:
    print(f"Step {index}/{total}: {title}", file=stdout)


def _run_flow(*, args, config: CLIConfig, stdout, stderr) -> int:
    total_steps = 8
    registry_base = args.registry_base or config.registry_base
    timeout_seconds = max(1, int(args.request_timeout_seconds))
    poll_seconds = max(1, int(args.poll_seconds))

    _print_step(stdout, index=1, total=total_steps, title="ensuring local identity")
    try:
        identity, _, _ = load_or_create_identity(args.identity_file)
    except IdentityError as exc:
        print(f"identity error: {exc}", file=stderr)
        return 1

    client = RegistryClient(base_url=registry_base)

    _print_step(stdout, index=2, total=total_steps, title="ensuring identity anchor")
    try:
        client.submit_identity_anchor(
            {
                "agent_public_key_b64": identity.public_key_b64,
                "agent_id": identity.agent_id,
                "metadata": {"agent_name": args.agent_name},
            }
        )
    except RegistryUnavailableError as exc:
        message = str(exc).lower()
        if "409" not in message or "already" not in message:
            print(f"registry error: {exc}", file=stderr)
            return 2

    _print_step(stdout, index=3, total=total_steps, title="computing AMCS root and sequence")
    memory_root = args.memory_root
    sequence = args.sequence
    if memory_root is None or sequence is None:
        amcs_db_path = args.amcs_db or config.amcs_db_path
        try:
            amcs = get_amcs_root(amcs_db_path=amcs_db_path, agent_id=identity.agent_id)
        except AMCSError as exc:
            print(f"amcs error: {exc}", file=stderr)
            return 1
        if memory_root is None:
            memory_root = amcs.memory_root
        if sequence is None:
            sequence = amcs.sequence

    _print_step(stdout, index=4, total=total_steps, title="submitting continuity request")
    manifest = build_identity_manifest(
        {
            "AGENT.md": f"{args.agent_name}\n",
            "SOUL.md": "Purpose: continuity certification via iap-agent CLI\n",
        }
    )
    payload = build_continuity_request(
        agent_public_key_b64=identity.public_key_b64,
        agent_id=identity.agent_id,
        agent_name=args.agent_name,
        agent_custody_class=args.agent_custody_class,
        memory_root=memory_root,
        sequence=sequence,
        manifest_version=manifest["manifest_version"],
        manifest_hash=manifest["manifest_hash"],
    )
    signed_payload = sign_continuity_request(payload, identity.private_key_bytes)
    try:
        request_response = client.submit_continuity_request(signed_payload)
    except RegistryUnavailableError as exc:
        print(f"registry error: {exc}", file=stderr)
        return 2

    request_id = request_response.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        print("registry error: invalid response (missing request_id)", file=stderr)
        return 2

    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        output_dir = Path(config.sessions_dir) / "flows" / request_id
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        save_session_record(
            sessions_dir=str(output_dir),
            request_id=request_id,
            payload={
                "created_at": _utc_now_iso(),
                "registry_base": registry_base,
                "agent_id": identity.agent_id,
                "request_id": request_id,
                "request_payload": signed_payload,
                "response": request_response,
            },
        )
    except SessionError as exc:
        print(f"session error: {exc}", file=stderr)
        return 1

    _print_step(stdout, index=5, total=total_steps, title="resolving payment handoff")
    payment_info: dict
    stripe_session = None
    try:
        stripe_session = client.create_stripe_checkout_session(request_id=request_id)
    except RegistryUnavailableError:
        stripe_session = None

    if stripe_session is not None:
        checkout_url = stripe_session.get("checkout_url")
        payment_info = {
            "method": "stripe",
            "checkout_url": checkout_url,
            "session_id": stripe_session.get("session_id"),
            "payment_status": stripe_session.get("payment_status"),
        }
        if args.open_browser and isinstance(checkout_url, str):
            try:
                webbrowser.open(checkout_url, new=2)
            except Exception:  # pragma: no cover
                pass
    else:
        try:
            status_payload = client.get_continuity_status(request_id)
        except RegistryUnavailableError as exc:
            print(f"registry error: {exc}", file=stderr)
            return 2
        payment_info = {
            "method": "lnbits",
            "status": status_payload.get("status"),
            "lightning_invoice": status_payload.get("lightning_invoice"),
            "lnbits_payment_hash": status_payload.get("lnbits_payment_hash"),
        }

    _print_step(stdout, index=6, total=total_steps, title="waiting for certification")
    deadline = time.time() + timeout_seconds
    latest_status = None
    while time.time() < deadline:
        try:
            latest_status = client.get_continuity_status(request_id)
        except RegistryUnavailableError as exc:
            print(f"registry error: {exc}", file=stderr)
            return 2
        if latest_status.get("status") == "CERTIFIED":
            break
        time.sleep(poll_seconds)
    if not latest_status or latest_status.get("status") != "CERTIFIED":
        print("timeout waiting for CERTIFIED status", file=stderr)
        return 3

    _print_step(stdout, index=7, total=total_steps, title="fetching certificate")
    try:
        cert_bundle = client.get_continuity_certificate(request_id)
    except RegistryUnavailableError as exc:
        print(f"registry error: {exc}", file=stderr)
        return 2
    cert_path = output_dir / "certificate.json"
    cert_path.write_text(json.dumps(cert_bundle, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    _print_step(stdout, index=8, total=total_steps, title="verifying certificate")
    try:
        key_payload = client.get_public_registry_key()
    except RegistryUnavailableError as exc:
        print(f"registry error: {exc}", file=stderr)
        return 2
    registry_public_key_b64 = key_payload.get("public_key_b64")
    if not isinstance(registry_public_key_b64, str) or not registry_public_key_b64:
        print("registry error: missing public_key_b64 in registry response", file=stderr)
        return 2

    ok, reason = verify_certificate_file(
        str(cert_path),
        registry_public_key_b64=registry_public_key_b64,
    )
    if not ok:
        print(f"verification failed: {reason}", file=stderr)
        return 4

    flow_summary = {
        "request_id": request_id,
        "agent_id": identity.agent_id,
        "registry_base": registry_base,
        "memory_root": memory_root,
        "sequence": sequence,
        "status": latest_status.get("status"),
        "payment": payment_info,
        "certificate_file": str(cert_path),
        "output_dir": str(output_dir),
        "verify_result": reason,
    }
    summary_path = output_dir / "flow_summary.json"
    summary_path.write_text(
        json.dumps(flow_summary, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )

    if args.json:
        print(json.dumps(flow_summary, sort_keys=True), file=stdout)
    else:
        print(f"request_id: {request_id}", file=stdout)
        print(f"status: {latest_status.get('status')}", file=stdout)
        print(f"certificate_file: {cert_path}", file=stdout)
        print(f"output_dir: {output_dir}", file=stdout)
    return 0


def main(argv: Sequence[str] | None = None, *, stdout=sys.stdout, stderr=sys.stderr) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        config = load_cli_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=stderr)
        return 1

    _emit_beta_warning(config, args.command, stderr)

    if args.command == "version":
        return _run_version(config=config, as_json=args.json, stdout=stdout)

    if args.command == "init":
        return _run_init(args=args, stdout=stdout, stderr=stderr)

    if args.command == "verify":
        return _run_verify(args=args, config=config, stdout=stdout, stderr=stderr)

    if args.command == "amcs":
        if args.amcs_command == "root":
            return _run_amcs_root(args=args, config=config, stdout=stdout, stderr=stderr)
        return _coming_soon(path=f"amcs {args.amcs_command}", stdout=stdout)

    if args.command == "anchor":
        if args.anchor_command == "issue":
            return _run_anchor_issue(args=args, config=config, stdout=stdout, stderr=stderr)
        return _coming_soon(path=f"anchor {args.anchor_command}", stdout=stdout)

    if args.command == "continuity":
        if args.continuity_command == "request":
            return _run_continuity_request(args=args, config=config, stdout=stdout, stderr=stderr)
        if args.continuity_command == "pay":
            return _run_continuity_pay(args=args, config=config, stdout=stdout, stderr=stderr)
        if args.continuity_command == "wait":
            return _run_continuity_wait(args=args, config=config, stdout=stdout, stderr=stderr)
        if args.continuity_command == "cert":
            return _run_continuity_cert(args=args, config=config, stdout=stdout, stderr=stderr)
        return _coming_soon(path=f"continuity {args.continuity_command}", stdout=stdout)

    if args.command == "flow":
        if args.flow_command == "run":
            return _run_flow(args=args, config=config, stdout=stdout, stderr=stderr)
        return _coming_soon(path=f"flow {args.flow_command}", stdout=stdout)

    print("unknown command", file=stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
