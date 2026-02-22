# Quickstart: First Certificate in 10 Minutes

Run from your `iap-sdk` environment.

## 1) Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
```

## 2) Initialize local identity

```bash
iap-agent init --show-public --json
```

## 3) Ensure identity anchor at registry

```bash
iap-agent anchor issue --registry-base http://localhost:8080 --agent-name "Atlas"
```

## 4) Create continuity request from local AMCS

```bash
iap-agent continuity request --registry-base http://localhost:8080 --json
```

## 5) Payment + certification + certificate

```bash
iap-agent continuity pay --request-id <request-id>
iap-agent continuity wait --request-id <request-id>
iap-agent continuity cert --request-id <request-id> --json
```

## 6) Offline verify certificate

```bash
iap-agent verify ./certificate.json --registry-base http://localhost:8080
```

## One-command path

```bash
iap-agent flow run --registry-base http://localhost:8080 --output-dir ./artifacts
```
