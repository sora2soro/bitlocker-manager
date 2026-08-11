#!/usr/bin/env python3
"""BitLocker Manager — Unlock Helper.

A tiny helper that runs on the OPERATOR'S PC. The web UI's "Unlock" button pings it
on 127.0.0.1; the helper fetches the recovery key from the app and writes it onto the
Pico (the CIRCUITPY drive). The operator never sees the key and never copies a token.

Flow when the operator clicks Unlock:
  browser  -> app POST /checkouts            (opens a checkout, gets a single-use token)
  browser  -> helper POST /load {token,...}  (hands the token to this helper)
  helper   -> app POST /checkouts/{id}/provision  (fetches the key with the token)
  helper   -> writes  blm_secret.txt  to the Pico

Run it (leave the window open while using the app):
    python helper/blm-helper.py

Security:
  * Binds to 127.0.0.1 only (not reachable from the network).
  * Only accepts requests from allow-listed web origins (edit ALLOWED_ORIGINS for prod).
  * The key lives only in this helper's memory and on the Pico — never in the browser.
"""
from __future__ import annotations

import json
import os
import string
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST, PORT = "127.0.0.1", 7333

# Web UI origins allowed to talk to this helper. Add your production UI origin here.
ALLOWED_ORIGINS = {
    "http://localhost:8000",
    "http://127.0.0.1:8000",
}


def find_pico():
    """Return the CIRCUITPY drive root (e.g. 'E:\\\\') on Windows, else None."""
    if os.name != "nt":
        return None
    import ctypes
    kernel32 = ctypes.windll.kernel32
    for letter in string.ascii_uppercase:
        root = f"{letter}:\\"
        vol = ctypes.create_unicode_buffer(1024)
        fs = ctypes.create_unicode_buffer(1024)
        ok = kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(root), vol, ctypes.sizeof(vol),
            None, None, None, fs, ctypes.sizeof(fs),
        )
        if ok and vol.value == "CIRCUITPY":
            return root
    return None


def app_post(api: str, path: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(api.rstrip("/") + path, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


class Handler(BaseHTTPRequestHandler):
    def _cors(self):
        origin = self.headers.get("Origin", "")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "content-type")
            self.send_header("Access-Control-Allow-Private-Network", "true")

    def _json(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self._cors()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self.path == "/status":
            drive = find_pico()
            return self._json(200, {"running": True, "pico": drive is not None,
                                    "drive": (drive[:2] if drive else None)})
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/load":
            return self._json(404, {"error": "not found"})
        origin = self.headers.get("Origin", "")
        if origin and origin not in ALLOWED_ORIGINS:
            return self._json(403, {"error": "origin not allowed"})
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode())
        except Exception:
            return self._json(400, {"error": "bad request"})

        drive = find_pico()
        if not drive:
            return self._json(409, {"error": "No Pico found — plug in the CIRCUITPY device."})
        try:
            resp = app_post(body["api"], f"/checkouts/{body['checkout_id']}/provision",
                            {"provisioning_token": body["token"], "usb_serial": f"CIRCUITPY-{drive[:2]}"})
            key = resp["key_material"]
        except Exception as e:
            return self._json(502, {"error": f"could not fetch key from app: {e}"})
        try:
            with open(os.path.join(drive, "blm_secret.txt"), "w") as f:
                f.write(key)
            key = None
        except Exception as e:
            return self._json(500, {"error": f"could not write to Pico: {e}"})
        self._json(200, {"ok": True, "drive": drive[:2]})

    def log_message(self, *args):
        pass  # keep the console quiet


def main():
    print(f"BitLocker Manager — Unlock Helper listening on http://{HOST}:{PORT}")
    print("Keep this window open while using the app. Press Ctrl+C to stop.")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
