"""Parsers for the import wizard.

Two flavours:

* parse_recovery_txt(text, filename) — the Windows-generated BitLocker recovery text
  file. Pulls the Identifier and 48-digit Recovery Key from inside the file, and
  hostname/site/serial from the filename convention:
      BitLocker_Recovery_Key_{Identifier}_{Serial}_{Hostname}.TXT

* parse_csv(csv_text) — a spreadsheet exported from Google Sheets / Excel.
  Auto-detects the target columns (Hostname, Site, Identifier, Recovery Key)
  by matching common header variants, so operators don't have to reshape the file.
"""
from __future__ import annotations

import csv
import io
import re

_GUID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
_KEY48 = re.compile(r"\d{6}(?:-\d{6}){7}")

# Column-header synonyms for the CSV importer (case/space/underscore-insensitive).
COLUMN_ALIASES = {
    "hostname":       {"hostname", "host name", "pc name", "computer name", "device name", "name"},
    "site":           {"site", "location", "office", "branch"},
    "key_identifier": {"identifier", "bitlocker id", "recovery key id", "key id", "id"},
    "key_material":   {"recovery key", "bitlocker recovery key", "key", "recovery id",
                       "recovery password", "password"},
    "serial":         {"serial", "serial number", "sn", "service tag"},
}


def _norm(s: str) -> str:
    return re.sub(r"[\s_\-]+", " ", s.strip().lower())


def parse_recovery_txt(text: str, filename: str = "") -> dict:
    """Parse a BitLocker recovery .txt file.

    Returns a dict with as many of these as could be found:
    hostname, site, serial, key_identifier, key_material.
    Raises ValueError if the file has no identifier or recovery key.
    """
    ident = _GUID.search(text)
    key = _KEY48.search(text)
    if not ident or not key:
        raise ValueError("file does not look like a BitLocker recovery key file "
                         "(missing Identifier or 48-digit Recovery Key)")
    out = {"key_identifier": ident.group(0).upper(),
           "key_material": key.group(0)}
    # Try the standard filename convention: BitLocker_Recovery_Key_{ID}_{Serial}_{Host}.TXT
    if filename:
        stem = re.sub(r"\.txt$", "", filename, flags=re.I)
        m = re.match(r"BitLocker[_\s]Recovery[_\s]Key[_\s]"
                     r"([0-9A-Fa-f\-]{36})[_\s]([^_\s]+)[_\s](.+)$", stem, re.I)
        if m:
            file_ident, serial, hostname = m.group(1), m.group(2), m.group(3)
            out["serial"] = serial
            out["hostname"] = hostname
            # Site prefix: everything before the first hyphen in the hostname (e.g. MAT-LTP-016 -> MAT)
            if "-" in hostname:
                out["site"] = hostname.split("-", 1)[0]
            # Sanity check: identifier in filename should match identifier in body
            if file_ident.upper() != out["key_identifier"].upper():
                out["_warning"] = "filename identifier does not match file body"
    return out


def parse_csv(csv_text: str) -> tuple[list[dict], dict, list[str]]:
    """Parse a CSV spreadsheet export.

    Returns (rows, mapping, warnings) where:
      rows     — list of dicts with keys hostname/site/key_identifier/key_material (+ serial)
      mapping  — which source column mapped to which target field (for the preview UI)
      warnings — issues found (missing columns, bad rows)
    """
    warnings: list[str] = []
    reader = csv.reader(io.StringIO(csv_text))
    headers = next(reader, None)
    if not headers:
        raise ValueError("empty CSV")
    # Auto-map source columns to target fields via aliases.
    mapping: dict[str, int] = {}
    for idx, h in enumerate(headers):
        n = _norm(h)
        for target, aliases in COLUMN_ALIASES.items():
            if target in mapping:
                continue
            if n in aliases:
                mapping[target] = idx
                break
    missing = [t for t in ("hostname", "site", "key_identifier", "key_material") if t not in mapping]
    if missing:
        warnings.append(
            f"couldn't auto-map columns: {', '.join(missing)}. "
            f"Headers seen: {', '.join(headers)}"
        )
    rows: list[dict] = []
    for i, raw in enumerate(reader, start=2):     # start=2 because header is row 1
        if not any(raw):
            continue
        try:
            row = {t: (raw[idx].strip() if idx < len(raw) else "") for t, idx in mapping.items()}
        except IndexError:
            warnings.append(f"row {i}: fewer columns than headers"); continue
        # Skip clearly empty / incomplete rows quietly
        if not row.get("hostname") or not row.get("key_material"):
            continue
        # Validate the 48-digit recovery key shape
        if not _KEY48.fullmatch(row["key_material"]):
            warnings.append(f"row {i} ({row.get('hostname','?')}): recovery key doesn't match 48-digit format")
            continue
        rows.append(row)
    return rows, {k: headers[v] for k, v in mapping.items()}, warnings
