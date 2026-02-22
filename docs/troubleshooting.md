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
- check local/prod port differences (`http://localhost:8080` vs TLS domain)

## request remains `WAITING_PAYMENT`

- verify payment actually completed in provider dashboard
- confirm webhook delivery and secret match
- run:

```bash
iap-agent continuity wait --request-id <request-id> --timeout-seconds 600
```

## verification failed

- fetch current registry public key:

```bash
iap-agent verify ./certificate.json --registry-base http://localhost:8080
```

- if strict lineage checks are required, provide previous certificate and identity anchor:

```bash
iap-agent verify ./certificate.json --profile strict --identity-anchor ./identity_anchor.json --previous-certificate ./prev_cert.json
```
