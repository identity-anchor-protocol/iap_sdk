# iap-sdk

Python SDK for Identity Anchor Protocol (IAP) request signing, state continuity tracking, and offline verification.

## Install

Published package:

```bash
python -m pip install -U pip
python -m pip install iap-agent
iap version
iap-agent version
```

Local editable development install:

```bash
python -m pip install -e ".[dev]"
```

## What this package provides

- Deterministic `agent_id` derivation from Ed25519 public keys
- Canonical request builders and signers for continuity, lineage, key rotation
- Registry API client helpers
- Offline certificate verification (including identity-anchor checks)
- Liveness and transparency helper utilities

IAP tracks agent state evolution.
It does not reduce LLM sampling randomness.

## Quick example

```python
from iap_sdk import build_continuity_request, sign_continuity_request

payload = build_continuity_request(
    agent_public_key_b64="...",
    agent_id="ed25519:...",
    memory_root="a" * 64,
    sequence=1,
    manifest_version="IAM-1",
    manifest_hash="b" * 64,
)
signed = sign_continuity_request(payload, private_key_bytes=b"...")
```

## Run tests

```bash
pytest
```

## Reproducible install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
iap-agent version
```

For a clean-room install smoke test, run:

```bash
./scripts/smoke_install.sh
```

Validate CLI snippets in docs:

```bash
python scripts/validate_doc_commands.py
```

## CLI (beta)

Install editable and run:

```bash
python -m pip install -e ".[dev]"
iap version
iap init
iap track
iap anchor --local-only
iap commit "updated agent objective"
iap verify ./certificate.json --registry-public-key-b64 <key>

# Legacy CLI remains supported in v0.1.x:
iap-agent continuity request --registry-base https://registry.ia-protocol.com --json
```

### CLI exit codes

- `0`: success
- `1`: validation/config/user input error
- `2`: network/registry unavailable
- `3`: timeout waiting for certification
- `4`: verification failure

### Version compatibility

See `/COMPATIBILITY.md` for pinned SDK/protocol/registry API assumptions.

## Docs

- `/docs/quickstart-first-certificate.md`
- `/docs/e2e-user-walkthrough.md`
- `/docs/e2e-dev-local-walkthrough.md`
- `/docs/operator-runbook-payments.md`
- `/docs/local-amcs-privacy-model.md`
- `/docs/lnbits-vs-stripe-flow.md`
- `/docs/troubleshooting.md`
- `/docs/migration-cli-first.md`
- `/docs/transition-terminology.md`
- `/examples/state-drift-demo/README.md`

## Drift demo

Run the transition demo in under 5 minutes:

```bash
python examples/state-drift-demo/demo.py
```

Expected:
- `verify_before_ok=True`
- `verify_after_ok=False`

### Beta mode config

Default config path:

`~/.iap_agent/config.toml`

Example:

```toml
beta_mode = true
maturity_level = "beta"
registry_base = "https://registry.ia-protocol.com"
amcs_db_path = "./amcs.db"
```

Environment override:

```bash
export IAP_REGISTRY_BASE="https://registry.ia-protocol.com"
```

Local development override example:

```toml
registry_base = "http://localhost:8080"
```
