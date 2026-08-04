# BitLocker Manager

Key-custody, accountability, and plug-and-play unlock for a BitLocker fleet.
Design spec: see `bitlocker-manager-design-spec.md`. This repo is the field-test build.

## Status

| Phase | Component | State |
|-------|-----------|-------|
| M1 | Vault core — envelope encryption, schema, hash-chained audit | built, 21 tests green |
| M1b | Backfill script (`tools/backfill.ps1`) | ready to field-validate |
| M2 | FastAPI service — auth, MFA, RBAC, endpoints | built, tested |
| M4 | Agent (`agent/blm-agent.ps1`) + Pico HID (`agent/pico/code.py`) | ready to field-validate |
| M5 | Operator UI (`ui/index.html`, Bootstrap 4 / SB Admin 2) | built |
| — | Admin/seed tool (`tools/seed.py`) | built, smoke-tested |

## Start here

- **Install & deploy:** `INSTALL.md`
- **How to use it:** `USER_GUIDE.md`

## Quick start

```bash
pip install -r requirements.txt
python -m pytest -q                                    # 21 passed
python -m tools.seed add-operator --username boss --role super_admin --password 'CHANGE-ME'
pip install uvicorn && uvicorn app.api:create_app --factory --port 8000
# UI at /ui/  ·  API docs at /docs
```

## Layout

```
app/          FastAPI service + vault core (crypto, models, audit, vault, api, deps, security, config, db)
tests/        21 tests, each mapped to a security requirement
tools/        seed.py (operators/MFA), backfill.ps1 (M1b)
agent/        blm-agent.ps1 (M4), pico/code.py (HID rig)
ui/           index.html (operator UI, M5)
INSTALL.md    deployment
USER_GUIDE.md workflows + field-test checklist
```

## Honest limits for field testing
- SR6 KEK-to-login binding and agent↔service mutual-TLS are deferred (documented in INSTALL §6).
- `manage-bde` output parsing (rotate/backfill) and Pico timing may need per-environment tweaks.
- The .NET production agent is a later port; PowerShell is used now for fast iteration.
