# Upgrade Guide

Upgrading `iap-agent` does not rotate identity by itself.

## What stays the same

- The SDK version can change without changing `agent_id`.
- `agent_id` remains the same as long as you keep using the same identity file.
- Ordinary tracked-state changes after an upgrade should usually be recorded as a new continuity event.

## When continuity is the right path

Use continuity when:

- you upgraded the SDK/package
- you added or updated tracked files such as `AGENT.md`, `SOUL.md`, or `SKILL.md`
- you are still the same agent with the same key material

## When lineage is the right path

Use lineage only when the user explicitly chooses a new generation relationship, for example:

- key or custody transfer
- intentional semantic handoff to a successor agent
- explicit fork / descendant semantics

Do not treat routine package upgrades as lineage by default.

## Pre-upgrade safety check

Run this before requesting new certificates after a software update:

```bash
iap-agent upgrade status --json
```

If the SDK warns that local `.iap` metadata is older than the current expectation, inspect the
safe local migration first:

```bash
iap-agent upgrade migrate --json
```

Then apply the non-destructive metadata/schema refresh:

```bash
iap-agent upgrade migrate --apply --json
```

This reports:

- installed SDK version
- the current identity path
- whether the current identity is project-local or global
- local state sequence
- registry-supported features
- latest registry continuity sequence for the current `agent_id`

If the registry sequence is ahead of local state, resume the same identity and continue from the
latest known sequence, or initialize a new project-local identity if this should be a separate
agent.

## Safe upgrade sequence

```bash
python -m pip install -U iap-agent
iap-agent upgrade status --json
iap-agent upgrade migrate --json
iap-agent registry status --json
```

## Certificate version naming

The current beta deployment intentionally uses two version labels:

- `certificate_version` stays frozen at `IAP-0.1`
- continuity `certificate_type` stays `IAP-Continuity-0.2`

That continuity subtype is a compatibility identifier, not a separate protocol
line. Identity, continuity, lineage, and key rotation all still belong to the
same `IAP-0.1` protocol family.

If your operator gave you an account token for self-service quota checks, you can also inspect your
remaining allowance directly:

```bash
iap-agent registry set-base --base "https://registry.ia-protocol.com"
iap-agent registry set-api-key --api-key "iapk_live_optional"
iap-agent account set-token --token "iapt_live_optional"
iap-agent registry check --json
iap-agent account usage --json
```

Or do the same bootstrap in one command:

```bash
iap-agent setup --registry-base "https://registry.ia-protocol.com" --registry-api-key "iapk_live_optional" --account-token "iapt_live_optional" --check --json
```

If you are preparing a user handoff, generate the exact command block you want them to paste:

```bash
iap-agent account handoff --registry-base "https://registry.ia-protocol.com" --registry-api-key "iapk_live_optional" --account-token "iapt_live_optional" --json
```

Environment overrides still work if you need a temporary shell-specific value:

```bash
export IAP_ACCOUNT_TOKEN="iapt_live_optional"
```

Then, if your tracked state changed after the upgrade:

1. append new state to AMCS
2. compute the new `memory_root`
3. request a new continuity certificate

## Need help?

For upgrade issues, unexpected identity reuse, or compatibility questions, contact:

- `admin@ia-protocol.com`
