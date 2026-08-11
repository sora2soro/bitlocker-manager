# BitLocker Manager — Admin & Developer Manual

A maintenance manual for the person who owns this codebase. It answers one
question over and over: **"I want to change X — which file do I open, and what
do I edit?"** It also documents every configuration variable, the database
schema and how to change it, the Raspberry Pi Pico firmware, and a full
from-scratch setup.

This is written to be read alongside the code in an editor (or Claude Code).
Section 1 is the map; the rest is detail.

---

## 0. The 60-second mental model

Three programs, one database.

1. **The server** (`app/`, Python/FastAPI) — holds the encrypted keys, checks
   logins, serves the web UI, writes the audit log. Runs on one internal box.
2. **The web UI** (`ui/index.html`, one HTML file) — what people click. It talks
   to the server over HTTP and to the local Unlock Helper over `127.0.0.1`.
3. **The unlock rig** (`agent/`) — a tiny local helper (`unlock-helper.py`) plus
   the Pico firmware (`agent/pico/code.py`). The helper writes the recovery key
   onto the Pico; the Pico types it into a locked laptop.

The key material is **never stored in plaintext**. It's encrypted with a random
per-key data key (DEK), and that DEK is itself encrypted by a master key (the
KEK) derived from `BLM_KEK_PASSPHRASE`. Lose that passphrase and every stored key
is gone — so escrow it (Zoho Vault) before enrolling anything real.

---

## 1. "Where do I edit that?" — the file map

| I want to change… | Open this file | Look for |
|---|---|---|
| Anything you see on screen (buttons, tables, modals, colours, labels) | `ui/index.html` | It's a single self-contained file: HTML at the top, one big `<script>` at the bottom. |
| An API rule / endpoint (what the server does, who's allowed) | `app/api.py` | `create_app()` — every endpoint is an `@app.<method>(...)` inside it. |
| The database shape (tables, columns) | `app/models.py` | One class per table. |
| Request/response field validation | `app/schemas.py` | Pydantic models: `...Create`, `...Update`, `...Out`. |
| Encryption / how keys are wrapped | `app/crypto.py` | `SoftwareKekProvider`, `encrypt_key_material`, `decrypt_key_material`. |
| Key lifecycle (enrol, rotate, reveal, provision) | `app/vault.py` | `enroll_key`, `rotate_key`, `reveal_key`, `get_key_for_provisioning`. |
| Passwords, JWT tokens, MFA codes | `app/security.py` | `hash_password`, `verify_password`, `verify_totp`, `create_token`. |
| Who can call what (roles, site scoping) | `app/deps.py` | `require_role`, `visible_sites`, `get_current_operator`. |
| The tamper-evident audit chain | `app/audit.py` | `append_audit`, `verify_chain`. |
| Import parsing (BitLocker `.txt`, CSV) | `app/importers.py` | `parse_recovery_txt`, `parse_csv`. |
| Config / secrets / env vars | `app/config.py` | `Settings` dataclass. |
| DB engine + auto-migrations + site seeding | `app/db.py` | `run_light_migrations`, `seed_default_sites`. |
| The command-line admin tool (create users) | `tools/seed.py` | `add_operator`, `list_operators`, `remove_operator`. |
| The Pico "type-the-key" firmware | `agent/pico/code.py` | `USE_NUMPAD`, `ARM_DELAY_S`, `main()`. |
| The local bridge that writes keys to the Pico | `agent/unlock-helper.py` | `find_circuitpy`, `_load`, `HOST/PORT`. |
| Tests (your safety net) | `tests/test_api.py`, `tests/test_vault_core.py` | Run `python -m pytest -q`. |

**Rule of thumb:** a change is usually *three files* — the model (`models.py`),
the schema (`schemas.py`), and the endpoint (`api.py`) on the server; plus
`ui/index.html` for the screen. The Site dropdown feature, for example, touched
exactly those four.

---

## 2. Full setup guide (from zero)

### 2.1 Prerequisites
- **Python 3.11+** on the server box.
- A Raspberry Pi **Pico** (or Pico W) for the unlock rig.
- Target laptops running Windows Pro/Enterprise (for `manage-bde`).

### 2.2 Install and self-test
```bash
cd bitlocker-manager
python -m venv .venv
. .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m pytest -q            # expect: all tests pass
```

### 2.3 Set the secrets (never ship the dev defaults)
Generate strong values, then export them as environment variables:
```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"   # -> BLM_JWT_SECRET
python -c "import secrets; print(secrets.token_urlsafe(48))"   # -> BLM_KEK_PASSPHRASE
python -c "import os,base64; print(base64.b64encode(os.urandom(16)).decode())"  # -> BLM_KEK_SALT
```
Set at least `BLM_JWT_SECRET`, `BLM_KEK_PASSPHRASE`, `BLM_KEK_SALT`, and (in
production) `BLM_DB_URL` and `BLM_CORS_ORIGINS`. Full table in §3.

> Escrow `BLM_KEK_PASSPHRASE` + `BLM_KEK_SALT` in Zoho Vault **before** enrolling
> real keys. They are not in the database by design; losing them is unrecoverable.

### 2.4 Create the first Super Admin
Super Admins can only be made from the command line — never through the UI. That
is deliberate: it protects the highest privilege from a compromised web session.
```bash
python -m tools.seed add-operator --username boss --role super_admin --password 'CHANGE-ME'
```
It prints a TOTP secret and an `otpauth://` URI. Add it to Google Authenticator /
Authy (paste the URI into any "otpauth QR generator" to scan). List users with
`python -m tools.seed list-operators`.

### 2.5 Run the server
```bash
uvicorn app.api:create_app --factory --host 0.0.0.0 --port 8000
```
- Operator UI → `http://<server>:8000/ui/`
- Interactive API docs → `http://<server>:8000/docs`

On first launch the server auto-creates all tables and seeds the two default
sites (Filandia, Matina). No manual DB step is needed.

### 2.6 Prepare the Pico (once per device) — see §6
Flash CircuitPython, copy `adafruit_hid` into `/lib`, copy `agent/pico/code.py`
onto the drive as `code.py`.

### 2.7 On each operator's PC (the unlock station)
```bash
python agent/unlock-helper.py     # leave this window open while unlocking
```
This is the piece most people forget. The helper must run **on the same PC the
operator is sitting at, with the Pico plugged into that same PC** — not on the
server. See §7 for why.

### 2.8 Production hardening (short list)
- Put the server behind nginx/Caddy terminating **HTTPS**.
- Switch `BLM_DB_URL` to PostgreSQL (SQLite is fine for pilot; it serialises
  writes under concurrent load).
- Set `BLM_CORS_ORIGINS` to your real origins, not `*`.

---

## 3. Configuration variables (`app/config.py`)

Every setting is read from an environment variable with a dev default. Override
the insecure ones in production.

| Env var | Field | Default | What it does |
|---|---|---|---|
| `BLM_JWT_SECRET` | `jwt_secret` | `dev-insecure-...` | Signs login tokens. Rotating it logs everyone out. |
| `BLM_KEK_PASSPHRASE` | `kek_passphrase` | `dev-insecure-...` | Master secret the KEK is derived from. **Lose it = lose all keys.** |
| `BLM_KEK_SALT` | `kek_salt` | `dev-insecure-salt-16b` | Salt for KEK derivation; must be ≥16 bytes. Store with the passphrase. |
| `BLM_DB_URL` | `db_url` | `sqlite:///bitlocker_manager.db` | SQLAlchemy URL. Swap to `postgresql+psycopg://...` for prod. |
| `BLM_ACCESS_TTL` | `access_ttl_seconds` | `3600` | How long an access token is valid (seconds). |
| `BLM_MFA_TTL` | `mfa_ttl_seconds` | `300` | How long the intermediate "MFA pending" token lasts. |
| `BLM_CORS_ORIGINS` | `cors_origins` | `*` | Comma-separated origins allowed to call the API. Lock this down in prod. |

To **add a new setting**: add a field to the `Settings` dataclass reading from
`os.environ.get(...)`, then reference `settings.<field>` where you need it. Because
`Settings` is a frozen dataclass, values are read once at process start.

---

## 4. The database — schema, and how to change it

### 4.1 The tables (one class = one table, in `app/models.py`)

**`sites`** — the pick-list behind the Site and Scope dropdowns.
| Column | Type | Notes |
|---|---|---|
| `id` | str (uuid) | PK |
| `name` | str(64) | unique, indexed; this string is what devices/operators store |
| `code` | str(16), nullable | short code (e.g. `FIL`) |
| `is_active` | bool | soft-delete flag; inactive sites drop off the dropdown |
| `created_by` | FK → operators.id, nullable | who added it |
| `created_at` | datetime | |

**`devices`** — one row per managed machine.
| Column | Type | Notes |
|---|---|---|
| `id` | str (uuid) | PK |
| `hostname` | str(255) | indexed |
| `serial` | str(255), nullable | asset/serial number; blank ones show up in Data Quality |
| `volume_id` | str(64), nullable | BitLocker recovery key **ID** (the GUID shown on the recovery screen) |
| `site` | str(64) | stores a `sites.name` value |
| `department` | str(128), nullable | |
| `encryption_status` | str(32) | default `unknown` |
| `archived` / `archived_at` / `archived_by` | bool / datetime / FK | soft-delete; archived devices are hidden by default |
| `created_at` / `updated_at` | datetime | `updated_at` auto-bumps on change |

**`operators`** — user accounts.
| Column | Type | Notes |
|---|---|---|
| `id` | str (uuid) | PK |
| `username` | str(128) | unique, indexed |
| `password_hash` | str(255) | **Argon2 hash** — never plaintext |
| `first_name` / `last_name` | str(64), nullable | profile |
| `middle_initial` | str(4), nullable | stored without the dot |
| `job_title` | str(128), nullable | profile |
| `role` | str(32) | `operator` \| `admin` \| `auditor` \| `super_admin` |
| `scope` | str(64), nullable | a site name; null = all sites |
| `mfa_secret` | str(64), nullable | TOTP secret |
| `status` | str(32) | `active` \| `inactive` |

**`key_versions`** — the encrypted keys (append-only history; rotation adds rows).
| Column | Type | Notes |
|---|---|---|
| `id` | str (uuid) | PK |
| `device_id` | FK → devices.id | |
| `key_type` | str(16) | `recovery` \| `startup` |
| `key_identifier` | str(64), nullable | recovery key ID GUID |
| `encrypted_material` | bytes | `nonce ‖ ciphertext ‖ tag` |
| `wrapped_dek` | bytes | the DEK, encrypted by the KEK |
| `status` | str(16) | `active` \| `revoked` |
| `source` | str(16) | `setup` \| `backfill` \| `rotation` |
| `rotated_from` | FK → key_versions.id, nullable | links a new key to the one it replaced |
| `created_by` | FK → operators.id, nullable | |
| `created_at` / `revoked_at` | datetime | |

**`checkouts`** — one unlock session (open → provision → unlock → rotate → close).
Tracks `ticket_ref`, `usb_serial`, the timestamps, `rotation_confirmed`, `status`.

**`audit_log`** — append-only, **hash-chained**. Each row stores `prev_hash` and
`entry_hash`; `verify_chain()` walks the chain to prove nothing was altered or
deleted. `seq` (autoincrement integer) is the primary key and orders the chain.

### 4.2 How migrations work here (important)

There is **no Alembic**. Two mechanisms keep the DB in step with the models:

1. `Base.metadata.create_all(engine)` runs on startup and creates any **missing
   table** in full. So *adding a whole new table needs no migration code* — define
   the class and restart.
2. `run_light_migrations(engine)` in `app/db.py` handles **new columns on tables
   that already exist** (SQLite only), because `create_all` will not alter an
   existing table. It only ever `ADD`s columns — never drops.

`seed_default_sites(engine)` then makes sure the sites list is never empty and
backfills any site names already used by existing rows.

### 4.3 Recipe: ADD A COLUMN to an existing table
Example — add `phone` to operators:
1. **Model** (`app/models.py`): add to the `Operator` class:
   ```python
   phone: Mapped[str | None] = mapped_column(String(32), nullable=True)
   ```
   Make it `nullable=True` (or give a default) so existing rows are valid.
2. **Light migration** (`app/db.py`, inside `run_light_migrations`, in the
   operators block): add a line so live SQLite DBs get the column:
   ```python
   ("phone", "ALTER TABLE operators ADD COLUMN phone VARCHAR(32)"),
   ```
3. **Schema** (`app/schemas.py`): add `phone: str | None = None` to
   `OperatorCreate` / `OperatorUpdate` / `OperatorOut` as needed.
4. **Endpoint** (`app/api.py`): read/write it in `create_operator` /
   `update_operator` (and `_op_out` if it should appear in responses).
5. **UI** (`ui/index.html`): add the input to the user modal and include it in
   the `POST /operators` body.
6. Run `python -m pytest -q`.

### 4.4 Recipe: ADD A NEW TABLE
1. Define the class in `app/models.py` (copy the shape of `Site`).
2. Restart — `create_all` builds it. (No migration code needed.)
3. Add `...Create`/`...Out` schemas, endpoints in `api.py`, and UI as required.
4. If it should be seeded with defaults, add a `seed_*` function in `db.py` and
   call it where `seed_default_sites` is called (in `create_app`).

### 4.5 Recipe: DELETE / RENAME a column or table
SQLite can't cleanly drop or rename columns, and this project has no migration
framework, so do it deliberately:
- **New/empty environments:** remove it from `models.py`, delete the `.db` file,
  restart. Clean slate.
- **Live data you must keep:** dump the table, create the new shape, copy the
  rows over, swap. For a production PostgreSQL DB, do it with a normal SQL
  migration. Never edit the schema by hand while the service is running.
- **Dropping a whole table:** remove the class from `models.py` and drop the
  table in SQL yourself (`create_all` never deletes tables).

> Because the audit log is hash-chained, **never** delete or edit rows in
> `audit_log`. Adding columns to it is fine; mutating history breaks
> `verify_chain()` on purpose.

### 4.6 Inspecting the DB directly
```bash
sqlite3 bitlocker_manager.db ".tables"
sqlite3 bitlocker_manager.db "SELECT hostname, site, serial FROM devices LIMIT 10;"
```
`encrypted_material` and `wrapped_dek` are binary blobs — you cannot read keys
out of the DB without the KEK, which is the point.

---

## 5. The API layer (`app/api.py`)

Every endpoint lives inside `create_app()` and follows the same shape:
```python
@app.post("/sites", response_model=SiteOut, status_code=201)
def create_site(body: SiteCreate,                       # validated request body
                session=Depends(get_session),           # DB session
                operator: Operator = Depends(require_role("admin", "super_admin"))):
    ...
```
Three things to notice, because you'll copy this pattern:
- **`response_model=`** ties the return to a schema in `schemas.py`.
- **`Depends(get_session)`** injects a database session; **`Depends(get_kek)`**
  injects the encryption provider when an endpoint touches key material.
- **`Depends(require_role(...))`** is the authorization gate. Change the role
  tuple to change who may call it. Endpoints with no `require_role` but with
  `get_current_operator` allow any logged-in user.

### 5.1 Endpoint inventory (current)
| Method & path | Who (roles) | Purpose |
|---|---|---|
| `POST /auth/login` | anyone | username+password → MFA token (or access token if no MFA) |
| `POST /auth/mfa` | anyone with MFA token | TOTP code → access token |
| `GET /sites` | any logged-in | list sites for dropdowns (`?include_inactive=`) |
| `POST /sites` | admin, super | add a site (reactivates a soft-deleted one) |
| `POST /sites/{id}/deactivate` | admin, super | soft-delete a site (blocked if devices use it) |
| `GET /devices` | any logged-in | list/search (`?q=&limit=&offset=`), site-scoped |
| `POST /devices` | admin, super | create a device |
| `PATCH /devices/{id}` | super | edit a device |
| `POST /devices/{id}/archive` | super | soft-delete a device |
| `GET /devices/{id}` | any logged-in | one device |
| `POST /devices/{id}/keys` | operator, admin, super | enrol a key onto a device |
| `POST /checkouts` | operator, admin, super | open an unlock session |
| `POST /checkouts/{id}/provision` | (token) | helper fetches the key with the single-use token |
| `POST /checkouts/{id}/rotate` | (kek) | record the rotated key |
| `POST /checkouts/{id}/wipe` | — | mark the Pico wiped |
| `POST /checkouts/{id}/close` | operator, admin, super | close the session |
| `POST /devices/{id}/reveal` | super | break-glass key reveal (step-up, high-severity log) |
| `GET /audit` | auditor, admin, super | read the audit log |
| `GET /devices-quality/incomplete` | auditor, admin, super | records missing serial / hostname / key ID |
| `GET /operators` | super | list users |
| `POST /operators` | super | create user |
| `PATCH /operators/{id}` | super | edit user (role, scope, profile) |
| `POST /operators/{id}/activate` · `/deactivate` | super | enable/disable |
| `DELETE /operators/{id}` | super | delete (audit history is preserved) |
| `POST /import/parse-txt` · `/parse-csv` | admin, super | preview an import file |
| `POST /import/commit` | admin, super | commit previewed rows |
| `GET /export/inventory` · `/export/audit` | (varies) | CSV/XLSX export |

### 5.2 Recipe: add an endpoint
1. Add the request/response schema(s) to `app/schemas.py`.
2. Import them at the top of `app/api.py` (the big `from .schemas import (...)`).
3. Write the `@app.<method>(...)` function inside `create_app()`, next to related
   ones. Pick the right `require_role(...)`.
4. Call `append_audit(session, action="...", operator_id=operator.id, ...)` for
   anything security-relevant.
5. Add a test in `tests/test_api.py`; run `python -m pytest -q`.

### 5.3 Roles & site scoping (`app/deps.py`)
- **`require_role("admin", "super_admin")`** — 403s anyone outside the tuple.
- **`visible_sites(operator)`** — returns `{operator.scope}` for a scoped
  operator, else `None` (all sites). Endpoints that list data call this and add
  a `WHERE site IN (...)` filter, so an operator only ever sees their own site.
- The **four roles**: `operator` (runs unlocks, never sees keys), `admin`
  (manages devices/imports), `auditor` (reads logs/exports), `super_admin`
  (everything, incl. user management and break-glass reveal).

---

## 6. The Pico firmware (`agent/pico/code.py`)

### 6.1 What it does
Some laptop recovery screens accept **only typed digits** (no paste, no numpad
guarantees). The Pico pretends to be a USB keyboard, reads the recovery key from
a file on its own drive (`blm_secret.txt`), and types the 48 digits followed by
Enter. It's CircuitPython, so the program is literally the file named `code.py`
on the `CIRCUITPY` drive — it runs on power-up.

### 6.2 The variables you'll actually tune
| Variable | Default | Meaning / when to change |
|---|---|---|
| `SECRET_PATH` | `"/blm_secret.txt"` | File the key is read from. The helper writes this. |
| `ARM_DELAY_S` | `4.0` | Seconds to wait after power-up before typing. Increase if the recovery field isn't focused yet when typing starts. |
| `KEY_DELAY_S` | `0.012` | Gap between keystrokes. Increase (e.g. `0.03`) if a slow machine drops characters. |
| `USE_NUMPAD` | `False` | `False` = top-row number keys (no NumLock needed — the safe default). Flip to `True` only if digits come out wrong/as navigation at the recovery screen. |
| `TOPROW` / `NUMPAD` | maps | Digit → HID keycode maps. `DIGITS` picks one based on `USE_NUMPAD`. |
| `ENTER` | derived | `KEYPAD_ENTER` in numpad mode, else `ENTER`. |
| `LED` | `board.LED` | Onboard LED, used for status blinks. |

### 6.3 The LED status codes (in `blink()` / `main()`)
- **2 blinks** — no key loaded (`blm_secret.txt` missing/empty); does nothing.
- **3 blinks** — armed; waits `ARM_DELAY_S`, then types.
- **Solid on** — finished typing and pressed Enter.

### 6.4 Flashing a Pico (once per device)
1. Hold **BOOTSEL**, plug in the Pico → it mounts as `RPI-RP2`.
2. Drag the CircuitPython `.uf2` onto it → it reboots as `CIRCUITPY`.
3. Download Adafruit's CircuitPython bundle; copy the **`adafruit_hid`** folder
   into `CIRCUITPY/lib/`.
4. Copy `agent/pico/code.py` to the root of `CIRCUITPY` as `code.py`.

### 6.5 Bench test without touching a real laptop
Create `blm_secret.txt` on the Pico with some digits, open Notepad, click into
it, then replug/reset the Pico. It should type your digits and press Enter. If
they come out wrong, flip `USE_NUMPAD` and retry.

> The Pico only handles digits because the BitLocker recovery field is numeric.
> `read_key()` strips everything that isn't a digit, so a pasted-in dashed key
> still types correctly.

---

## 7. The unlock rig on the PC (`agent/unlock-helper.py`)

### 7.1 Why this exists
A browser cannot write to a USB drive (sandbox). So the "Unlock" button in the UI
can't put the key on the Pico by itself. The helper is a tiny local web server
that the browser calls; the helper fetches the key from the app (using a
single-use token the browser passes it) and writes it to the Pico. The operator
never sees or copies the key.

### 7.2 The golden rule (this is the bug you hit)
The helper looks for the Pico on **whatever machine the helper is running on**.
The UI calls `http://127.0.0.1:8765`, and `127.0.0.1` always means *the machine
the browser is running on*. Therefore:

> **The helper must run on the operator's own PC, with the Pico plugged into that
> same PC.** If the helper is only running on the server, an operator across the
> network hits nothing at their own `127.0.0.1`, or the server-side helper looks
> for a Pico that isn't there — which is exactly the "handler can't find the
> device" error.

Each unlock station therefore runs its own `python agent/unlock-helper.py`.

### 7.3 The variables
| Variable | Value | Meaning |
|---|---|---|
| `HOST, PORT` | `127.0.0.1, 8765` | localhost only — not reachable from the network. Must match `HELPER` in `ui/index.html`. |
| `SECRET_FILE` | `blm_secret.txt` | filename written to the Pico; must match `SECRET_PATH` in the Pico firmware. |

Key functions: `find_circuitpy()` (scans drive letters for a `CIRCUITPY` volume —
**Windows-only**, uses `GetVolumeInformationW`), `app_post()` (calls the server),
`_load()` (the actual fetch-key-and-write step). The `GET /` handler returns
`{"status":"ok","pico": <drive or null>}` so the UI can show whether a Pico is
present *on this PC*.

### 7.4 Serving the UI over plain HTTP: the Chrome gotcha
When the page is served from `http://<server>:8000` and calls
`http://127.0.0.1:8765`, Chrome's **Private Network Access** treats that as a
request into a more-private network and requires a CORS preflight. The helper
already answers it (`Access-Control-Allow-Private-Network: true` in `_cors()`),
but the robust fix is to serve the UI over **HTTPS**. If unlock silently fails
only over the network, this is the first thing to check.

---

## 8. The web UI (`ui/index.html`)

One file. Structure: Bootstrap 4 / SB Admin 2 markup, then a single `<script>`.

### 8.1 The variables and helpers to know
| Name | Meaning |
|---|---|
| `API` | Base URL for the server. `""` = same origin (the UI is served by the app at `/ui/`). |
| `HELPER` | `http://127.0.0.1:8765` — the local Unlock Helper. Must match the helper's `HOST/PORT`. |
| `TOKEN` | The current access token (kept in `sessionStorage` as `blm_token`). |
| `SITES` | Cached list from `GET /sites`, used to fill dropdowns. |
| `devQuery` / `devPage` / `devPageSize` | Device search + pagination state. |
| `claims()` | Decodes the JWT payload to read role/scope for showing/hiding UI. |
| `api(path, opts)` | Wrapper around `fetch` that attaches the token and parses errors. |
| `show(id)` | Shorthand for `document.getElementById`. |
| `esc(s)` | HTML-escapes a string before it goes into the DOM. |
| `fillSiteSelect(id, selected, blankLabel)` | Populates a `<select>` from `SITES`. |

### 8.2 Show/hide by role
Elements carry CSS classes toggled at login in `finishLogin()`:
`app-admin-site` (the "+ add site" button; admins/super), `app-audit`
(auditor/admin/super — e.g. the Data Quality button), `app-super`
(super-only — e.g. user management), and `app-hidden` (the base "off" state).
To gate a new element, add the right class and it'll reveal itself for the right
roles.

### 8.3 Recipe: wire a button to an endpoint
```javascript
show("my-btn").onclick = async () => {
  try {
    const r = await api("/my/endpoint", { method: "POST", body: JSON.stringify({...}) });
    // update the DOM with r
  } catch (e) { /* show e.message */ }
};
```
Match the JSON body to the endpoint's `...Create`/`...Update` schema, and let the
`require_role` on the server do the real enforcement — the CSS classes are only
cosmetic.

---

## 9. Everyday operations

- **Add a user:** UI → gear/Settings → Add user (super only), or
  `python -m tools.seed add-operator ...` from the CLI.
- **Add a site:** the `+` next to Site in the device form, or `POST /sites`.
- **Find dirty data:** the **Data quality** button → lists devices missing a
  serial, hostname, or recovery key ID, with inline Edit.
- **Prove the audit log is intact:** call `verify_chain(session)` (in
  `app/audit.py`) — returns `True` if the hash chain is unbroken.
- **Back up:** the SQLite file **and** the KEK passphrase/salt (stored
  separately). A backup of one without the other is useless.

---

## 10. Before you commit any change

```bash
python -m pytest -q          # the whole suite must stay green
```
The tests are your contract. If you add an endpoint or column, add a test for it.
When something breaks over the network but not locally, re-read §7 first — nine
times out of ten it's the helper location or the HTTPS/Private-Network gotcha,
not the code.
