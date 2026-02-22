# iap-sdk

Python SDK for Identity Anchor Protocol (IAP) request signing and offline certificate verification.

## Install

```bash
python -m pip install -e ".[dev]"
```

## What this package provides

- Deterministic `agent_id` derivation from Ed25519 public keys
- Canonical request builders and signers for continuity, lineage, key rotation
- Registry API client helpers
- Offline certificate verification (including identity-anchor checks)
- Liveness and transparency helper utilities

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

## CLI (beta)

Install editable and run:

```bash
python -m pip install -e ".[dev]"
iap-agent version
iap-agent version --json
iap-agent init
iap-agent init --show-public --json
iap-agent amcs root --amcs-db ./amcs.db --agent-id ed25519:...
iap-agent anchor issue --registry-base http://localhost:8080 --agent-name "Atlas"
```

### Beta mode config

Default config path:

`~/.iap_agent/config.toml`

Example:

```toml
beta_mode = true
maturity_level = "beta"
registry_base = "http://localhost:8080"
amcs_db_path = "./amcs.db"
```
