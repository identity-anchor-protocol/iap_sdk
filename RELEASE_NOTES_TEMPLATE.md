# Release Notes Template

Use this template for `iap-agent` release notes.

## Summary

- Version: `X.Y.Z`
- Release date: `YYYY-MM-DD`
- Protocol compatibility: `IAP-0.1`
- AMCS dependency floor: `iap-amcs >= A.B.C`

## Highlights

- Key user-visible improvements:
  - `...`
- Registry compatibility notes:
  - `...`

## Installation

```bash
python -m pip install -U iap-agent==X.Y.Z
```

## Upgrade Notes

- Existing `agent_id` values are preserved as long as the same identity file is reused.
- If the release changes tracked-state behavior, request a new continuity certificate after applying the change.
- If the release introduces a major identity/custody policy change, call it out explicitly here.

## Breaking Changes

- `None` / or list explicit breaking changes

## Validation Performed

- [ ] `python -m build`
- [ ] `twine check dist/*`
- [ ] clean virtualenv install
- [ ] `iap-agent --version`
- [ ] `python -c "import amcs; print('ok')"`
- [ ] targeted live verification against registry

## Security Notes

- New security-sensitive behavior:
  - `...`
- Known limitations retained:
  - `...`

## Links

- PyPI: `https://pypi.org/project/iap-agent/`
- Repo: `https://github.com/identity-anchor-protocol/iap_sdk`
- Registry quickstart: `docs/quickstart-first-certificate.md`
