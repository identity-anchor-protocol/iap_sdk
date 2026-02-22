# Migration Guide: Script-First to CLI-First

This migration replaces custom scripts and raw API calls with `iap-agent` commands.

## Before

- hand-build continuity payloads
- invoke HTTP endpoints manually
- poll status via ad-hoc scripts
- fetch certificate with raw HTTP calls

## After

- use stable commands with standard exit codes
- use one guided command for end-to-end flow
- store artifacts in predictable output directories

## Mapping

| Old approach | CLI-first replacement |
| --- | --- |
| generate/load key pair manually | `iap-agent init` |
| read AMCS root with custom code | `iap-agent amcs root` |
| POST identity anchor endpoint | `iap-agent anchor issue` |
| POST continuity request endpoint | `iap-agent continuity request` |
| manual payment instructions | `iap-agent continuity pay` |
| custom polling script | `iap-agent continuity wait` |
| raw cert fetch | `iap-agent continuity cert` |
| custom verify script | `iap-agent verify` |
| full scripted orchestration | `iap-agent flow run` |

## Recommended migration sequence

1. Install `iap-sdk` and verify `iap-agent version`.
2. Replace identity bootstrap script with `iap-agent init`.
3. Replace request submission script with `iap-agent continuity request`.
4. Replace polling/certificate scripts with `wait` + `cert`.
5. Consolidate workflows around `flow run` where possible.
