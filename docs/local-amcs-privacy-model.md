# Local AMCS Privacy Model

`iap-sdk` is designed so sensitive memory data stays local.

## What stays local

- AMCS event store (`amcs.db`)
- event payloads and memory contents
- local private signing key (`~/.iap_agent/identity/ed25519.json`)
- manifest source files (for example `AGENT.md`, `SOUL.md`)

## What is sent to registry

- `agent_id`
- agent public key
- memory root hash
- monotonic sequence number
- manifest hash + manifest version
- request signature

The registry never needs raw AMCS events to issue continuity certificates.

## Practical guidance

- Keep AMCS DB on encrypted local storage.
- Never share the private key file.
- Use separate identities for development and production agents.
- Back up local identity and AMCS DB together to preserve continuity history.
