# End-to-End Walkthrough (User-Friendly)

This is a human-readable test from zero to certificate.

What you do:

1. Create (or load) your agent key pair.
2. Save `AGENT.md` and `SOUL.md` into local `amcs.db`.
3. Read the resulting `memory_root`.
4. Buy an Identity Anchor certificate.
5. Buy a Continuity certificate.
6. Download and verify the continuity certificate.

## 0) One-time setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
python -m pip install -e /path/to/AMCS-0.1
```

Set registry URL:

```bash
export REGISTRY_BASE="https://registry.ia-protocol.com"
```

## 1) Create your local agent identity

```bash
iap-agent init --show-public --json
```

You will get:

- `agent_id` (public identity)
- `public_key_b64` (public key)

## 2) Create agent files and store them in AMCS

Create files:

```bash
cat > AGENT.md <<'EOF'
# Atlas
Role: Personal AI assistant
EOF

cat > SOUL.md <<'EOF'
# Purpose
Help user reliably, safely, and with continuity.
EOF
```

Append both files to local AMCS:

```bash
python scripts/append_agent_files_to_amcs.py --amcs-db ./amcs.db --agent-id <agent_id> --agent-file ./AGENT.md --soul-file ./SOUL.md
```

This command prints the latest `memory_root_latest`.

## 3) Confirm AMCS root and sequence

```bash
iap-agent amcs root --amcs-db ./amcs.db --agent-id <agent_id> --json
```

## 4) Request Identity Anchor and pay

Stripe:

```bash
iap-agent anchor issue --registry-base "$REGISTRY_BASE" --agent-name "Atlas" --payment-provider stripe --open-browser --json
```

LNBits:

```bash
iap-agent anchor issue --registry-base "$REGISTRY_BASE" --agent-name "Atlas" --payment-provider lnbits --json
```

For LNBits, pay the `payment.lightning_invoice` shown in the JSON output.

## 5) Request Continuity and pay

Create request:

```bash
iap-agent continuity request --registry-base "$REGISTRY_BASE" --amcs-db ./amcs.db --json
```

Copy `request_id`, then pay:

Stripe:

```bash
iap-agent continuity pay --registry-base "$REGISTRY_BASE" --request-id <request_id> --payment-provider stripe --open-browser --json
```

LNBits:

```bash
iap-agent continuity pay --registry-base "$REGISTRY_BASE" --request-id <request_id> --payment-provider lnbits --json
```

## 6) Wait for certification, fetch certificate, verify

```bash
iap-agent continuity wait --registry-base "$REGISTRY_BASE" --request-id <request_id> --timeout-seconds 600 --poll-seconds 5 --json
iap-agent continuity cert --registry-base "$REGISTRY_BASE" --request-id <request_id> --output-file ./certificate.json --json
iap-agent verify ./certificate.json --registry-base "$REGISTRY_BASE" --json
```

Expected final result: `{"ok": true, "reason": "ok"}`.
