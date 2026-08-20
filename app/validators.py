"""Format validation + normalisation for BitLocker recovery data.

Two patterns, taken from what the recovery screen actually shows:

* Recovery Key ID (the "Identifier") — a GUID: 8-4-4-4-12 hex characters,
  e.g. ``0BCA25A7-DDF3-4E97-87F1-A643EB656942``.
* Recovery Key — eight groups of six digits (48 digits total),
  e.g. ``335357-052701-573265-124388-247709-400708-532015-331848``.

Normalisers are forgiving on input (spaces, missing/extra dashes, lowercase)
and emit the canonical dashed, upper-case form. Validators are strict.
"""
import re

RECOVERY_KEY_ID_RE = re.compile(
    r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$")
RECOVERY_KEY_RE = re.compile(r"^\d{6}(-\d{6}){7}$")

# how many characters live in each group, used by the normalisers and the UI
KEY_ID_GROUPS = (8, 4, 4, 4, 12)      # 32 hex chars
KEY_GROUPS = (6,) * 8                  # 48 digits


def normalize_recovery_key_id(raw: str) -> str:
    """Strip separators, upper-case, and re-insert dashes as 8-4-4-4-12.

    Raises ValueError if the result isn't exactly 32 hex characters.
    """
    hexchars = re.sub(r"[^0-9A-Fa-f]", "", raw or "").upper()
    if len(hexchars) != 32:
        raise ValueError(
            f"Recovery Key ID must be 32 hex characters (got {len(hexchars)}). "
            "Expected the 8-4-4-4-12 Identifier from the recovery screen.")
    out, i = [], 0
    for g in KEY_ID_GROUPS:
        out.append(hexchars[i:i + g]); i += g
    return "-".join(out)


def is_valid_recovery_key_id(s: str) -> bool:
    return bool(RECOVERY_KEY_ID_RE.match(s or ""))


def normalize_recovery_key(raw: str) -> str:
    """Strip separators and re-group as eight 6-digit blocks.

    Raises ValueError if the result isn't exactly 48 digits.
    """
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) != 48:
        raise ValueError(
            f"Recovery Key must be 48 digits, i.e. 8 groups of 6 "
            f"(got {len(digits)}).")
    return "-".join(digits[i:i + 6] for i in range(0, 48, 6))


def is_valid_recovery_key(s: str) -> bool:
    return bool(RECOVERY_KEY_RE.match(s or ""))
