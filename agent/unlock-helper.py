"""BitLocker Manager — Unlock Helper (runs on the operator's PC).

The web UI cannot write to a USB drive (browser sandbox). This tiny local program
bridges that gap: the browser's "Unlock" button pings it, and the helper fetches
the recovery key from the app and writes it onto the Pico (the CIRCUITPY drive).

The operator never sees or copies the key or the token — the browser hands the
(single-use) token to the helper automatically over localhost.

Run it on the operator's machine and leave it open:
    python agent/unlock-helper.py

It listens on http://127.0.0.1:8765 (localhost only — not reachable from the network).
"""
from __future__ import annotations

import json
import ssl
import string
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST, PORT = "127.0.0.1", 8765
SECRET_FILE = "blm_secret.txt"


def find_circuitpy() -> str | None:
    """Return the drive (e.g. 'E:') whose volume label is CIRCUITPY, or None."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
    except Exception:
        return None
    import ctypes
    for letter in string.ascii_uppercase:
        root = f"{letter}:\\"
        label = ctypes.create_unicode_buffer(1024)
        fs = ctypes.create_unicode_buffer(1024)
        ok = kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(root), label, 1024, None, None, None, fs, 1024)
        if ok and label.value == "CIRCUITPY":
            return f"{letter}:"
    return None


def app_post(api: str, path: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(api.rstrip("/") + path, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    ctx = ssl.create_default_context() if api.startswith("https") else None
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        return json.loads(resp.read().decode())


class Handler(BaseHTTPRequestHandler):
    def _cors(self):
        origin = self.headers.get("Origin", "*")
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Private-Network", "true")

    def do_OPTIONS(self):
        self.send_response(204); self._cors(); self.end_headers()

    def do_GET(self):
        # health check + Pico presence, so the UI can show a status indicator
        self.send_response(200); self._cors()
        self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps({"status": "ok", "pico": find_circuitpy()}).encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or "{}")
            result = self._load(body); code = 200
        except urllib.error.HTTPError as e:
            result = {"ok": False, "error": f"app returned {e.code} — token may be expired/used"}; code = 400
        except Exception as e:
            result = {"ok": False, "error": str(e)}; code = 400
        self.send_response(code); self._cors()
        self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps(result).encode())

    def _load(self, body: dict) -> dict:
        api = body["api"]
        checkout_id = body["checkout_id"]
        token = body["provisioning_token"]
        pico = find_circuitpy()
        if not pico:
            raise RuntimeError("Pico not found — plug in the CIRCUITPY drive and try again")
        r = app_post(api, f"/checkouts/{checkout_id}/provision",
                     {"provisioning_token": token, "usb_serial": f"CIRCUITPY-{pico}"})
        key = r["key_material"]                      # in memory only
        with open(f"{pico}\\{SECRET_FILE}", "w", encoding="ascii", newline="") as f:
            f.write(key)
        key = None
        return {"ok": True, "drive": pico}

    def log_message(self, *args):
        pass  # keep the console quiet


if __name__ == "__main__":
    print("BitLocker Manager — Unlock Helper")
    print(f"Listening on http://{HOST}:{PORT}  (localhost only)")
    print("Leave this window open while unlocking machines. Press Ctrl+C to stop.")
    try:
        HTTPServer((HOST, PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nUnlock Helper stopped.")
