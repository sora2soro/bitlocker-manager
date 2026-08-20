# KB: Setting Up BitLocker Manager — Linux Server & Windows Operator Stations

**Audience:** IT / Desktop Support staff deploying BitLocker Manager.
**Architecture:** the **server** runs on Linux (Ubuntu); **operator stations**
run on Windows (that's where the Unlock Helper and the Pi Pico live). BitLocker
itself is a Windows feature, so the machines being *recovered* are Windows — only
the management server is Linux.

```
   ┌─────────────────────────┐         HTTPS/HTTP          ┌────────────────────────────┐
   │  UBUNTU SERVER          │  <───────────────────────>  │  WINDOWS OPERATOR STATION  │
   │  FastAPI app + UI + DB   │                             │  Browser + Unlock Helper   │
   │  http://<server>:8000    │                             │  127.0.0.1:8765 + Pi Pico  │
   └─────────────────────────┘                             └────────────────────────────┘
```

There are two independent setups below. Do **Part A (server)** once. Do
**Part B (operator station)** on each PC that will perform unlocks.

---

## Part A — Server setup (Ubuntu)

### A0. Prerequisites
- Ubuntu 22.04 / 24.04, with a static IP on the LAN (operators reach it by IP).
- Python 3.11 or newer.
- The `bitlocker-manager` project files copied to the server (e.g. `/opt/bitlocker-manager`).

### A1. Install Python and create a virtual environment
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
cd /opt/bitlocker-manager
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### A2. Verify the build before configuring anything
```bash
python -m pytest -q          # expect: 32 passed
```
If the tests pass, the application is intact. If not, stop and resolve that first.

### A3. Generate real secrets (do NOT ship the dev defaults)
The app derives its master encryption key and signs logins from environment
variables. Generate strong values:
```bash
python -c "import secrets; print('JWT   :', secrets.token_urlsafe(48))"
python -c "import secrets; print('KEKPW :', secrets.token_urlsafe(48))"
python -c "import os,base64; print('SALT  :', base64.b64encode(os.urandom(16)).decode())"
```

> **Escrow the KEK passphrase and salt in Zoho Vault before enrolling any real
> keys.** They are deliberately not stored in the database. If they are lost,
> every stored recovery key is unrecoverable. This is the single most important
> step in the whole deployment.

### A4. Store the configuration
Create an environment file `/opt/bitlocker-manager/blm.env` (readable only by the
service account):
```bash
BLM_JWT_SECRET=<the JWT value from A3>
BLM_KEK_PASSPHRASE=<the KEKPW value from A3>
BLM_KEK_SALT=<the SALT value from A3>
BLM_DB_URL=sqlite:////opt/bitlocker-manager/bitlocker_manager.db
BLM_CORS_ORIGINS=http://<server-ip>:8000
```
```bash
chmod 600 /opt/bitlocker-manager/blm.env
```
- **Pilot:** SQLite (shown above) is fine.
- **Production:** switch `BLM_DB_URL` to PostgreSQL
  (`postgresql+psycopg://user:pass@localhost/blm`) — SQLite serialises writes
  under concurrent operators.

### A5. Create the first Super Admin (CLI only)
Super Admins can only be created from the command line — never through the web UI
(deliberate: it protects the highest privilege). With the venv active and the
env file loaded:
```bash
set -a; source blm.env; set +a
python -m tools.seed add-operator --username boss --role super_admin --password 'CHANGE-ME-STRONG'
```
It prints a TOTP secret and an `otpauth://` URI — add it to Google Authenticator
or Authy (paste the URI into any otpauth-QR generator to scan). List accounts any
time with `python -m tools.seed list-operators`.

### A6. Run the server
Quick manual start (for testing):
```bash
set -a; source blm.env; set +a
uvicorn app.api:create_app --factory --host 0.0.0.0 --port 8000
```
- Operator UI → `http://<server-ip>:8000/ui/`
- API docs → `http://<server-ip>:8000/docs`

On first launch the app auto-creates all tables and seeds the default sites
(Filandia, Matina). No manual database step is required.

### A7. Run it as a service (recommended, so it survives reboots)
Create `/etc/systemd/system/blm.service`:
```ini
[Unit]
Description=BitLocker Manager
After=network.target

[Service]
User=blm
WorkingDirectory=/opt/bitlocker-manager
EnvironmentFile=/opt/bitlocker-manager/blm.env
ExecStart=/opt/bitlocker-manager/.venv/bin/uvicorn app.api:create_app --factory --host 0.0.0.0 --port 8000
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
```bash
sudo useradd -r -s /usr/sbin/nologin blm 2>/dev/null || true
sudo chown -R blm:blm /opt/bitlocker-manager
sudo systemctl daemon-reload
sudo systemctl enable --now blm
sudo systemctl status blm            # confirm active (running)
```

### A8. Open the firewall port
```bash
sudo ufw allow 8000/tcp
```

### A9. (Strongly recommended) Serve over HTTPS
Operators' browsers call a helper on `127.0.0.1` from the app page. When the app
is plain **http://**, Chrome's Private Network Access can block that call and the
Unlock button fails even with the helper running. Put a reverse proxy in front
that terminates HTTPS (Caddy is simplest):
```bash
sudo apt install -y caddy
# /etc/caddy/Caddyfile:
#   blm.yourdomain.local {
#       reverse_proxy 127.0.0.1:8000
#   }
sudo systemctl restart caddy
```
Then set `BLM_CORS_ORIGINS` to the `https://` origin. This isn't strictly
required for a same-PC test, but it's the robust fix for network unlocks — see
Part B / Troubleshooting.

**Server is ready.** Note the URL operators will use: `http://<server-ip>:8000/ui/`
(or your HTTPS hostname).

---

## Part B — Operator station setup (Windows)

Each unlock station needs three things: the **Unlock Helper** (auto-starting),
a **prepared Pi Pico**, and a **browser** pointed at the server. The operator PC
does **not** need Python or the project repo — the helper ships as a single exe.

### B0. One-time: build the helper exe (on any one Windows PC with Python)
Do this **once**, on a build machine, to produce the file you'll copy everywhere:
```powershell
cd bitlocker-manager
powershell -ExecutionPolicy Bypass -File packaging\build-helper.ps1
```
This produces `dist\blm-helper.exe` — a single self-contained file. (PyInstaller
builds a Windows exe on Windows; you can't build it on the Linux server.)

### B1. Install the helper on the operator PC
Copy two files into the same folder on the operator PC — `blm-helper.exe` and
`packaging\install-helper.ps1` — then run:
```powershell
powershell -ExecutionPolicy Bypass -File install-helper.ps1
```
This copies the exe to `%LOCALAPPDATA%\BLMHelper`, registers a **logon Scheduled
Task** so it always starts, and launches it now. The operator never runs a script
again. (You can push these two files + the one command through Intune/MDM to roll
out to every station at once. Uninstall with `-Uninstall`.)

### B2. Verify the helper is listening
In the operator PC's browser, open:
```
http://127.0.0.1:8765/
```
You should see `{"status":"ok","pico":...}`. If nothing loads, the helper isn't
running — re-run B1 or start `blm-helper.exe` manually.

> **Why localhost:** the helper listens only on `127.0.0.1`, which always means
> "this same PC." That's why it must run on the operator's own machine with the
> Pico plugged into that machine — not on the server.

### B3. Prepare the Pi Pico (once per Pico)
1. Hold **BOOTSEL**, plug the Pico in → it mounts as `RPI-RP2`.
2. Drag the CircuitPython `.uf2` onto it → it reboots as `CIRCUITPY`.
3. Download the Adafruit CircuitPython library bundle; copy the **`adafruit_hid`**
   folder into `CIRCUITPY\lib\`.
4. Copy `agent\pico\code.py` to the root of `CIRCUITPY` as `code.py`.

Bench test: create a `blm_secret.txt` on the Pico with a few digits, open Notepad,
click into it, then reset/replug the Pico — it should type the digits and press
Enter. (If digits come out wrong, flip `USE_NUMPAD` in `code.py`.)

### B4. Point the operator at the server
Bookmark the server URL from Part A: `http://<server-ip>:8000/ui/` (or the HTTPS
hostname). The operator logs in with the account an Admin/Super created for them
plus their MFA code.

### B5. First real unlock (sanity check)
1. Helper running on this PC (B2 shows `{"status":"ok"}`), Pico plugged into this PC.
2. In the UI, find the device → **Unlock…** → the helper loads the key onto the Pico.
3. Plug the Pico into the locked machine — it types the key and unlocks it.

**Operator station is ready.** Repeat Part B for each unlock station.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "Couldn't reach the Unlock Helper" | Helper not running on **this** PC | Re-run `install-helper.ps1`; confirm `http://127.0.0.1:8765/` loads on that PC. |
| Helper loads at `127.0.0.1:8765` but Unlock still fails | Chrome **Private Network Access** blocking an HTTP page from calling localhost | Serve the app over **HTTPS** (Part A9). Confirm via F12 → Console: a "private network"/CORS message points here. |
| `{"status":"ok","pico":null}` | No Pico detected on this PC | Plug the Pico into this machine; check it mounts as `CIRCUITPY`. |
| `python` not found on a Windows PC | Only the Microsoft Store stub is present | Not needed on operator PCs (use the exe). On the build PC, install from python.org and tick "Add to PATH". |
| Server unreachable from operator PC | Firewall / wrong IP | `sudo ufw allow 8000/tcp`; confirm the server IP and that both are on the same LAN. |
| Login works but no devices show | Operator is site-scoped | Expected — operators only see their own site's devices. Admins/Supers see all. |
| Can't create a Super Admin in the UI | By design | Super Admins are CLI-only: `python -m tools.seed add-operator --role super_admin …` on the server. |

## Related documents
- `ADMIN_MANUAL.md` — which file to edit for which change; DB schema; variables.
- `packaging/README.md` — helper exe build/install detail and the HTTPS dependency.
- `docs/SECURITY_TESTING.md` — how to demonstrate encryption / SQLi / tamper controls.
- `INSTALL.md`, `USER_GUIDE.md` — original quick-start and end-user guides.

## Known limitation (roadmap, not a setup step)
The Unlock Helper is currently **Windows-only** — it locates the Pico via a
Windows API. If you ever move operator stations to Ubuntu, the helper's
drive-detection needs a small cross-platform patch first. The server, by
contrast, is fully cross-platform and runs cleanly on Ubuntu as documented above.
