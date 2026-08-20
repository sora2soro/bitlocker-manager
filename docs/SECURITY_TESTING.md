# BitLocker Manager — Security Testing & Demonstration Guide

A hands-on guide to demonstrate, to your admin/management, that three specific
risks are addressed: **database encryption**, **SQL injection**, and **data
tampering**. Each section states the threat, the control in the code (with file
references), and a copy-paste demonstration that produces visible proof.

These are demonstrations of the controls already built in — not a substitute for
an independent third-party penetration test. If this system ever holds real
recovery keys for a regulated environment, commission an external assessment as
well. Run everything below against a **test database with dummy data**, never
production, and never paste real recovery keys into a terminal.

Setup used by the demos:

```bash
cd bitlocker-manager
python -m venv .venv && . .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
# create some dummy laptops so there's data to inspect
python tools\make-dummy-laptops.ps1             # or use the import wizard in the UI
```

---

## 1. Database Encryption

**Threat.** Someone obtains a copy of the database file (backup, stolen disk,
casual copy) and reads recovery keys straight out of it.

**Control.** Keys are never stored in plaintext. Each key is sealed with
envelope encryption: a random per-key data key (DEK) encrypts the key material
with **AES-256-GCM**, and that DEK is itself wrapped by a master key (the KEK)
derived from `BLM_KEK_PASSPHRASE` via a memory-hard KDF. The database stores only
two opaque blobs per key — `encrypted_material` and `wrapped_dek` — and never the
passphrase. Code: `app/crypto.py` (`encrypt_key_material`, `decrypt_key_material`,
`SoftwareKekProvider`); columns defined in `app/models.py` (`KeyVersion`).

### Demo 1a — the key is not in the database

Open the raw database and try to find a recovery key. Enroll a device with a
known key first (via the UI), say Recovery Key `335357-052701-…`, then:

```bash
# dump the encrypted-key table as text and search for the plaintext key
sqlite3 bitlocker_manager.db "SELECT hex(encrypted_material), hex(wrapped_dek) FROM key_versions;"
# search the ENTIRE raw file for the digits you entered — expect NO match
python -c "open('found.txt','w').write('MATCH' if b'335357' in open('bitlocker_manager.db','rb').read() else 'NOT FOUND')"
type found.txt        # Windows  (Linux: cat found.txt)
```

**Proof shown:** the table prints only hex ciphertext, and the raw-file search
prints `NOT FOUND` — the digits you typed are nowhere in the file.

### Demo 1b — without the passphrase, the ciphertext is useless

```bash
python - <<'PY'
from app.crypto import SoftwareKekProvider, decrypt_key_material
from app.db import make_engine, session_factory
from app.models import KeyVersion
from app.config import Settings
s = session_factory(make_engine(Settings().db_url))()
kv = s.query(KeyVersion).first()
# try to decrypt with the WRONG passphrase
wrong = SoftwareKekProvider(b"the-wrong-passphrase", Settings().kek_salt)
try:
    decrypt_key_material(kv.encrypted_material, kv.wrapped_dek, wrong)
    print("DECRYPTED — control FAILED")
except Exception as e:
    print("REJECTED with wrong key:", type(e).__name__)
PY
```

**Proof shown:** decryption with the wrong passphrase raises an
authentication/`InvalidTag` error — the data can't be recovered without the exact
KEK. (AES-GCM also detects any bit-flip in the ciphertext, so a corrupted or
altered blob fails the same way — see §3.)

**Talking point for your admin.** The security reduces to protecting one secret,
`BLM_KEK_PASSPHRASE`, which lives in an environment variable / Zoho Vault, not in
the database or the repo. A stolen database backup is inert on its own.

---

## 2. SQL Injection

**Threat.** An attacker puts SQL fragments into an input field (hostname, search
box, login) hoping to read or destroy data — e.g. `'; DROP TABLE devices;--`.

**Control.** Every database query goes through **SQLAlchemy with bound
parameters** — user input is always passed as a *value*, never concatenated into
SQL text. Searches use `.where(Column.ilike(param))`; there is no string-built
SQL anywhere in `app/`. Inputs are additionally shape-checked by Pydantic schemas
(`app/schemas.py`) and the recovery-data validators (`app/validators.py`).

### Demo 2a — inject through the search box

Log in, then hammer the device search with a classic payload:

```bash
# TOKEN = a valid access token from POST /auth/login + /auth/mfa
curl "http://127.0.0.1:8000/devices?q=%27%3B%20DROP%20TABLE%20devices%3B--" \
     -H "Authorization: Bearer $TOKEN"
# then confirm the table still exists and still has rows:
sqlite3 bitlocker_manager.db "SELECT count(*) FROM devices;"
```

**Proof shown:** the search returns a normal (usually empty) result set, no error,
and the `devices` table is intact with its row count unchanged. The payload was
treated as a literal string to search for, not as SQL.

### Demo 2b — inject through the login field

```bash
curl -X POST http://127.0.0.1:8000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin'\'' OR 1=1--","password":"x"}'
```

**Proof shown:** returns `401` (invalid credentials). The injected `OR 1=1--`
does nothing because the username is bound as a parameter and simply doesn't
match any row.

### Demo 2c — prove it at the code level (optional, most convincing)

```bash
python - <<'PY'
from sqlalchemy import select
from app.db import make_engine, session_factory
from app.models import Device
s = session_factory(make_engine("sqlite:///bitlocker_manager.db"))()
payload = "'; DROP TABLE devices;--"
rows = s.execute(select(Device).where(Device.hostname.ilike(f"%{payload}%"))).scalars().all()
print("rows matching the payload:", len(rows))     # 0, and table still exists
print("devices table still present:", s.execute(select(Device)).first() is not None or "empty-but-present")
PY
```

**Proof shown:** the malicious string is used purely as a search term; the table
is never dropped.

---

## 3. Data Tampering

**Threat.** Someone with access to the database edits a row to (a) alter a stored
key, or (b) quietly change/delete audit history to hide an action.

**Control — encrypted data.** AES-256-GCM is *authenticated* encryption: it
carries an integrity tag, so any edit to `encrypted_material` or `wrapped_dek` is
detected on decrypt and rejected. You can't silently change a stored key.

**Control — audit log.** `audit_log` is **append-only and hash-chained**: each
row stores the hash of the previous row plus a hash of its own contents
(`app/audit.py`, `append_audit` / `verify_chain`). Deleting, reordering, or
editing any row breaks the chain, and `verify_chain()` reports exactly where.

### Demo 3a — tamper with an encrypted key

```bash
python - <<'PY'
from app.crypto import SoftwareKekProvider, decrypt_key_material
from app.db import make_engine, session_factory
from app.models import KeyVersion
from app.config import Settings
s = session_factory(make_engine(Settings().db_url))()
kv = s.query(KeyVersion).first()
kek = SoftwareKekProvider(Settings().kek_passphrase, Settings().kek_salt)
blob = bytearray(kv.encrypted_material)
blob[-1] ^= 0x01                       # flip one bit of the ciphertext
try:
    decrypt_key_material(bytes(blob), kv.wrapped_dek, kek)
    print("accepted tampered data — control FAILED")
except Exception as e:
    print("tamper detected:", type(e).__name__)   # InvalidTag / auth failure
PY
```

**Proof shown:** a single flipped bit makes decryption fail — tampering is caught,
not silently served.

### Demo 3b — tamper with the audit log

```bash
python - <<'PY'
from app.db import make_engine, session_factory
from app.audit import verify_chain
from app.models import AuditLog
from app.config import Settings
eng = make_engine(Settings().db_url); s = session_factory(eng)()
print("chain valid before tamper:", verify_chain(s))     # True

# now maliciously edit a historical row directly in SQL
row = s.query(AuditLog).order_by(AuditLog.seq).first()
row.action = "totally_legit_nothing_to_see"
s.commit()

s2 = session_factory(eng)()
print("chain valid after tamper:", verify_chain(s2))      # False — detected
PY
```

**Proof shown:** `verify_chain` returns `True` on the intact log and `False`
after the row is edited — the tampering is provable. In the UI/report you can
surface this as a one-line "audit integrity: VERIFIED / BROKEN" check.

### Demo 3c — deletion is detected too

Delete any audit row in SQL (`DELETE FROM audit_log WHERE seq = <n>;`) and re-run
`verify_chain` — it returns `False`, because the next row's stored `prev_hash` no
longer matches. There is no way to remove an action from history without leaving
evidence.

---

## 4. One-page summary for management

| Risk | Control | How it's proven |
|---|---|---|
| Stolen DB reveals keys | AES-256-GCM envelope encryption; KEK held outside the DB | Raw-file search finds no key; wrong passphrase can't decrypt (Demo 1) |
| SQL injection | Parameterised SQLAlchemy queries + schema validation | Injection payloads in search/login do nothing; table intact (Demo 2) |
| Key tampering | Authenticated encryption detects any edit | One flipped bit → decrypt fails (Demo 3a) |
| Hiding actions | Append-only hash-chained audit log | Editing/deleting a row → `verify_chain` = False (Demo 3b/3c) |

**Residual items to raise honestly**, so the demo is credible rather than a sales
pitch: recovery keys and passwords cross the network in cleartext until the app
is served over **HTTPS** (currently plain HTTP on the LAN); the strength of the
whole encryption scheme depends on `BLM_KEK_PASSPHRASE` being strong and secret;
and this is an internal demonstration, not an independent audit. Those are the
next things to close, and naming them builds trust.
