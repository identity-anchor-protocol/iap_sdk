# Security Assumptions

This document captures the security baseline for `iap-agent` v0.1.x.

## Trust assumptions

- The verifier has a trusted registry public key (`public_key_b64`) before running strict offline verification.
- The local machine storing the identity key and AMCS database is trusted by the operator.
- Registry certificates are meaningful only if the verifier trusts the registry key they pinned.

## What the SDK protects

- Canonical request construction for signing and verification.
- Deterministic `agent_id` derivation from the Ed25519 public key.
- Offline registry signature verification.
- Clear verification failures when a signed field changes.

## What the SDK does not protect by itself

- Compromise of the user machine holding the private key.
- A privileged attacker rewriting the local AMCS database before any external checkpoint.
- Behavioral guarantees about the model or agent beyond attested state continuity.
- Trust-on-first-use key fetches in place of a pinned trust root.

## Operational requirements

- Keep the identity private key on the client machine unless the user explicitly exports it.
- Prefer `iap-agent init --project-local` for a genuinely new agent.
- Treat `~/.iap_agent/identity/ed25519.json` as a long-lived global identity if reused.
- Use strict verification with an explicit `--registry-public-key-b64` value.
- Keep upgrade changes additive in v0.1.x; do not silently rotate identity.

## Dependency audit baseline

- CI runs `pip-audit` against runtime dependencies declared in `pyproject.toml`.
- Findings must be reviewed before release.
- If a dependency issue is accepted temporarily, record the rationale in the release notes.

## Reporting issues

For security-relevant concerns, upgrade failures, or suspicious verification behavior, contact:

- `admin@ia-protocol.com`
