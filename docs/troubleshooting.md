# Troubleshooting

## `ModuleNotFoundError` for `requests` / `fastapi` / other deps

Use one interpreter consistently:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

## `iap-agent: command not found`

The environment is not activated or script path is missing:

```bash
source .venv/bin/activate
python -m pip install -e ".[dev]"
iap-agent version
```

## `connection refused` to registry

- verify registry is running
- verify `registry_base` in config or command override
- check local/prod endpoint differences (`http://localhost:8080` vs `https://registry.ia-protocol.com`)

## `missing account token` or `invalid account token`

If you are using account-scoped quota checks:

```bash
iap-agent account usage --json
```

store the token in config:

```bash
iap-agent account set-token --token "iapt_live_optional"
```

or configure it manually in:

```toml
account_token = "iapt_live_optional"
```

or via:

```bash
export IAP_ACCOUNT_TOKEN="iapt_live_optional"
```

If the CLI says the token is invalid, request a fresh account token from your operator. On success,
the latest account usage snapshot is also written locally under your configured `sessions_dir` as
`account_usage_last.json`.

## `account tier quota exceeded`

This means the API key itself may still be valid, but the linked account has reached its monthly
tier cap. You have three options:

- ask your operator to increase the account-level quota
- switch to a different account/API key with remaining entitlement
- retry without `IAP_REGISTRY_API_KEY` so the request uses the payment flow instead

## request remains `WAITING_PAYMENT`

- verify payment actually completed in provider dashboard
- confirm webhook delivery and secret match
- run:

```bash
iap-agent continuity wait --request-id <request-id> --timeout-seconds 600
```

## verification failed

- fetch current registry public key, then verify against that pinned trust anchor:

```bash
REGISTRY_PUBLIC_KEY_B64="$(curl -s https://registry.ia-protocol.com/registry/public-key | jq -r .public_key_b64)"
iap-agent verify ./continuity_record.json --registry-public-key-b64 "$REGISTRY_PUBLIC_KEY_B64"
```

- if strict lineage checks are required, provide previous certificate and identity anchor:

```bash
iap-agent verify ./continuity_record.json --profile strict --identity-anchor ./identity_anchor_record.json --previous-certificate ./prev_continuity_record.json
```
