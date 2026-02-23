# Release Runbook (PyPI)

This project publishes `iap-agent` to PyPI using GitHub Actions Trusted Publishing.

## 1) Preconditions

- PyPI account exists and has 2FA enabled.
- PyPI project `iap-agent` is configured with Trusted Publisher for:
  - GitHub org/user: `identity-anchor-protocol`
  - Repository: `iap_sdk`
  - Workflow: `.github/workflows/release.yml`
- `main` branch is green.

## 2) Bump version

Edit `/Users/Dirk/code/IAP/iap-sdk/pyproject.toml`:

- `[project].version = "X.Y.Z"`

Commit and push:

```bash
git checkout main
git pull --ff-only origin main
git add pyproject.toml
git commit -m "release: bump version to X.Y.Z"
git push origin main
```

## 3) Local preflight

```bash
python -m pip install -U pip build twine
rm -rf dist build *.egg-info src/*.egg-info
python -m build
twine check dist/*
```

## 4) Tag and publish

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

Tag push triggers `.github/workflows/release.yml` and publishes automatically.

## 5) Post-publish verification

```bash
python3 -m venv /tmp/iap-pypi
source /tmp/iap-pypi/bin/activate
python -m pip install -U pip
python -m pip install iap-agent
iap-agent --help
iap-agent --version
iap-agent version --json
```

## 6) Hotfix process

If release has issues:

1. Fix on `main`.
2. Bump patch version (for example `0.1.0 -> 0.1.1`).
3. Tag and push new tag `v0.1.1`.

Do not overwrite existing PyPI versions.
