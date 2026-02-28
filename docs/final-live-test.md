# Final Live Test (Go / No-Go)

This is the closeout checklist for the hardened v0.1 release candidate.

Use it after:

1. fresh `iap-agent` install on a clean machine or clean virtualenv
2. fresh registry deployment or redeploy from the documented production steps

## Preconditions

- `iap-agent >= 0.1.5`
- registry is reachable at `REGISTRY_BASE`
- you can issue one fresh identity-anchor and one fresh continuity record
- you have the resulting:
  - `identity_anchor_record.json`
  - `continuity_record.json`

## Step 1: Fresh install smoke

```bash
python -m pip install -U pip
python -m pip install -U iap-agent
python -c "import amcs; print('ok')"
iap-agent --version
```

Expected:
- package installs cleanly
- `amcs` import works

## Step 2: Fresh agent

Use a new folder and create a project-local identity:

```bash
mkdir -p ./iap-live-test
cd ./iap-live-test
iap-agent init --project-local --show-public --json
```

Expected:
- `agent_id` returned
- identity path is inside `./.iap/`

## Step 3: Anchor + first continuity

Follow the current first-certificate flow:

- append tracked files with `iap-agent amcs append`
- compute root with `iap-agent amcs root`
- issue an identity anchor
- issue a continuity request
- complete quota or payment gating as applicable
- fetch `identity_anchor_record.json`
- fetch `continuity_record.json`

Use the standard walkthrough:

- `docs/quickstart-first-certificate.md`

## Step 4: Automated verification script

Run the scripted closeout checks:

```bash
python scripts/final_live_test.py \
  --registry-base "$REGISTRY_BASE" \
  --identity-anchor ./identity_anchor_record.json \
  --continuity-record ./continuity_record.json
```

This script verifies:
- `/health`
- `/healthz`
- `/registry/public-key`
- strict verification succeeds for the valid continuity chain
- strict verification fails after a deliberate tamper mutation

## Step 5: Quota enforcement (manual)

If you are using API key soft entitlements, test quota exhaustion explicitly:

1. create an API key with a very small monthly quota
2. use it for repeated issuance requests
3. confirm the registry returns:
   - `429`
   - a clear message that the API key quota is exhausted

## Go / No-Go Criteria

Release is acceptable only if all are true:

- fresh install works
- fresh project-local identity works
- valid continuity verification succeeds
- tampered continuity verification fails
- registry health endpoints are green
- quota gating behaves deterministically
