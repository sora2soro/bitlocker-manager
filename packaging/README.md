# Deploying the Unlock Helper (packaged `.exe`)

The Unlock Helper is the only piece that runs on an operator's PC. It's a small
localhost bridge (127.0.0.1:8765) that writes the recovery key onto the Pico —
the browser can't do that itself. This folder packages it so operator PCs need
**nothing** installed: no Python, no repo, no pip.

## Why an .exe and not a browser extension

A browser extension (or the web page's own JavaScript) is sandboxed and cannot
enumerate USB drives, write files to the Pico, or talk to serial devices. That
capability has to live in a native process outside the browser — which is exactly
what this helper is. So the deployment target is "a small native program that
auto-starts," not a plugin.

## One-time: build the exe (on a Windows dev machine with Python 3.11+)

```powershell
cd bitlocker-manager
powershell -ExecutionPolicy Bypass -File packaging\build-helper.ps1
```

Produces `dist\blm-helper.exe` — a single self-contained file. PyInstaller builds
a Windows exe **on Windows**; you can't cross-build it from Linux/Mac.

## Per operator PC: install + auto-start

Copy two files to the PC — `blm-helper.exe` and `install-helper.ps1` — into the
same folder, then:

```powershell
powershell -ExecutionPolicy Bypass -File install-helper.ps1
```

This copies the exe to `%LOCALAPPDATA%\BLMHelper`, registers a **logon Scheduled
Task** so it always starts, and launches it now. The operator never installs
Python or runs a script again. (Uninstall: add `-Uninstall`.)

You can push these two files + the one command through Intune/MDM as a package to
roll it out to every unlock station at once.

### Verify it's working on that PC

Open `http://127.0.0.1:8765/` in the browser — you should see
`{"status":"ok","pico":...}`. Then the Unlock button in the app will reach it.

## IMPORTANT dependency: HTTPS / Private Network Access

The `.exe` fixes "helper not installed." It does **not** fix the other possible
cause of "Couldn't reach the Unlock Helper": when the app is served over plain
**http://<server-ip>:port**, Chrome's Private Network Access can block the page
from calling `127.0.0.1` even though the helper is running.

Confirm which situation you're in **before** rolling the exe out widely: on a PC
where `http://127.0.0.1:8765/` loads fine but Unlock still fails, open DevTools
(F12) → Console at the click — if it mentions *private network* or *CORS*, you
also need to serve the app over **HTTPS** (a reverse proxy such as Caddy/nginx in
front of uvicorn). The helper already returns the required
`Access-Control-Allow-Private-Network` header, but HTTPS on the app side is the
robust fix. See `ADMIN_MANUAL.md` §7.4.

## Config

The helper is config-free: the browser passes it the server URL (`api`) and the
one-time token at call time, so the same exe works on every PC and against any
server. The only thing that must match is the port — `8765` — which appears in
both `agent/unlock-helper.py` (`HOST, PORT`) and `ui/index.html` (`HELPER`). Don't
change one without the other.
