# IAP Transition Terminology (v0.1.x)

This document defines the transition vocabulary for IAP as a debugging and audit layer for autonomous agent state evolution.

## Positioning

IAP tracks agent state evolution.
IAP does not reduce LLM sampling randomness.

## Primary Terms

Use these terms in user-facing UX and documentation:

* `state_root.json`
* `anchor_record.json`
* `continuity_record.json`
* `fork_root.json`

## Compatibility Terms (v0.1.x)

The existing ecosystem still includes certificate-oriented names.
In v0.1.x these remain valid for backward compatibility:

* `certificate.json`
* `Identity Certificate`
* `Continuity Certificate`
* `Lineage Certificate`

Compatibility rule:

* APIs and verifiers may continue to emit certificate fields.
* CLI and docs should prefer state/audit language by default.
* No cryptographic behavior changes are introduced by terminology updates.
