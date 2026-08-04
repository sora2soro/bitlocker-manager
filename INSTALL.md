# BitLocker Manager — Installation & Deployment

This covers a field-test install. Production hardening notes are called out at the end.

---

## 1. Components

| Component | Where it runs | Field-test status |
|-----------|---------------|-------------------|
| **Service + API + UI** (Python/FastAPI) | one internal server (or your PC) | ready, unit-tested |
| **Admin/seed tool** (Python) | same box as the service | ready |
| **Backfill script** (PowerShell) | each still-accessible Windows machine | ready to validate |
| **Agent** (PowerShell) | operator's Windows PC + the target | ready to validate |
| **Pico HID rig** (CircuitPython) | a Raspberry Pi Pico | ready to validate |

---

## 2. Install the service

Requires **Python 3.11+**.

```bash
cd bitlocker-manager
python -m venv .venv && . .venv/bin/activate     # optional
pip install -r requirements.txt
python -m pytest -q                              # expect: 21 passed
```

### 2.1 Configure (do NOT ship the dev defaults)

Set these environment variables. Generate strong values:

```bash
python -c "import secrets; print('BLM_JWT_SECRET =', secrets.token_urlsafe(48))"
python -c "import secrets; print('BLM_KEK_PASSPHRASE =', secrets.token_urlsafe(48))"
python -c "import os,base64; print('BLM_KEK_SALT =', base64.b64encode(os.urandom(16)).decode())"
```

| Variable | Meaning |
|----------|---------|
| `BLM_JWT_SECRET` | Signs auth tokens. Keep secret; rotating it logs everyone out. |
| `BLM_KEK_PASSPHRASE` | Derives the master key-encryption key. **If lost, stored keys are unrecoverable.** Back it up in a separate secrets manager (e.g. your existing Zoho Vault), never in the app DB. |
| `BLM_KEK_SALT` | Salt for KEK derivation. Store with the passphrase. |
| `BLM_DB_URL` | Default `sqlite:///bitlocker_manager.db`. Use PostgreSQL in production (below). |
| `BLM_CORS_ORIGINS` | Comma-separated origins allowed to call the API. Set to your DSE Site / inventory origins; avoid `*` in production. |

> **Critical:** the KEK passphrase/salt are the master secret. They are deliberately not in
> the database, so a stolen DB alone cannot decrypt keys — but that also means **losing them
> loses every stored key.** Escrow them safely and separately before you enrol anything real.

### 2.2 Create your first Super Admin

```bash
python -m tools.seed add-operator --username boss --role super_admin --password 'CHANGE-ME'
```

It prints a TOTP secret and an `otpauth://` URI — add it to Google Authenticator / Authy
(paste the URI into any "otpauth QR generator" to scan). Add more people:

```bash
python -m tools.seed add-operator --username cris --role operator --scope Filandia --password '...'
python -m tools.seed add-operator --username admin --role admin --password '...'
python -m tools.seed add-operator --username aud   --role auditor --password '...'
python -m tools.seed list-operators
```

Roles: `operator` (runs unlocks in their `--scope` site, never sees keys), `admin`
(enrol devices/users), `auditor` (read the log), `super_admin` (break-glass reveal).

### 2.3 Run it

```bash
pip install uvicorn
uvicorn app.api:create_app --factory --host 0.0.0.0 --port 8000
```

- Operator UI: `http://<server>:8000/ui/`
- API docs (interactive): `http://<server>:8000/docs`

---

## 3. Set up the unlock USB (Pi Pico HID rig)

For models whose recovery screen only accepts a typed key (your tested model):

1. Hold **BOOTSEL**, plug the Pico in, drag the **CircuitPython .uf2** onto the `RPI-RP2` drive.
2. Download Adafruit's CircuitPython bundle; copy the `adafruit_hid` folder into `/lib` on the `CIRCUITPY` drive.
3. Copy `agent/pico/code.py` to the Pico as `code.py`.

The Pico now waits for a `blm_secret.txt` (written by the agent) and types it at the recovery
screen. For models that *do* read a USB key file, use the agent's `-Mode native` instead — no Pico needed.

---

## 4. Set up the agent (operator PCs)

Copy `agent/blm-agent.ps1` to each operator's machine. In an elevated PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process RemoteSigned
.\blm-agent.ps1 login -Api https://<server>:8000 -User cris    # get a token for 'close'
```

`manage-bde` (built into Windows Pro/Enterprise) must be available for `rotate`.

---

## 5. Backfill your fleet (do this first — it's the real win)

On every machine you can still reach, capture its existing key into the vault:

```powershell
.\backfill.ps1 -Api https://<server>:8000 -AccessToken <token> -Site Filandia -Drive C:
```

Push it via your existing management tooling to hit the whole reachable fleet. This alone
retires the plaintext tracker and stops the key bleed.

---

## 6. Production hardening (after field test)

- **Database:** set `BLM_DB_URL` to PostgreSQL (`postgresql+psycopg://user:pass@host/blm`).
  The audit hash-chain stays valid across the switch (timestamps are normalized).
- **TLS:** run behind a reverse proxy (Caddy/nginx) terminating HTTPS. The agent and UI must
  use `https://`.
- **Service manager:** run under systemd (Linux) or NSSM (Windows) so it restarts on boot.
- **Backups:** back up the database **and**, separately, the KEK passphrase/salt.
- **Known deferrals (see spec §9):** (a) bind the KEK to per-operator login so no single
  service secret is enough for SR6; (b) mutual-TLS between agent and service; (c) CSP
  `frame-ancestors` for the DSE Site / inventory embeds; (d) a signed .NET agent. None block
  field testing; all are on the hardening list.
