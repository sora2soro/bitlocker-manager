"""Tamper-evident audit log (SR8).

Each entry's ``entry_hash`` = SHA-256(prev_hash + canonical(content)). A deleted
or edited row breaks the chain, which ``verify_chain`` detects. Even a Super Admin
cannot quietly rewrite history.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditLog

GENESIS = "0" * 64


def _norm_ts(timestamp) -> str | None:
    """Canonical naive-UTC ISO string.

    Timestamps are stored in UTC; some backends (e.g. SQLite) return them naive.
    Normalizing to naive-UTC makes the hash stable whether the value is read
    fresh (tz-aware) or round-tripped through the DB (naive).
    """
    if timestamp is None:
        return None
    if timestamp.tzinfo is not None:
        timestamp = timestamp.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return timestamp.isoformat()


def _canonical(prev_hash: str, *, timestamp, operator_id, device_id,
               checkout_id, action, severity, detail) -> str:
    payload = {
        "prev_hash": prev_hash,
        "timestamp": _norm_ts(timestamp),
        "operator_id": operator_id,
        "device_id": device_id,
        "checkout_id": checkout_id,
        "action": action,
        "severity": severity,
        "detail": detail,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _hash(prev_hash: str, **content) -> str:
    return hashlib.sha256(_canonical(prev_hash, **content).encode()).hexdigest()


def append_audit(session: Session, *, action: str, operator_id: str | None = None,
                 device_id: str | None = None, checkout_id: str | None = None,
                 severity: str = "info", detail: str | None = None) -> AuditLog:
    """Append one hash-chained entry. Flushes so ``seq`` is assigned."""
    last = session.execute(
        select(AuditLog).order_by(AuditLog.seq.desc()).limit(1)
    ).scalar_one_or_none()
    prev_hash = last.entry_hash if last else GENESIS

    from .models import _now  # local import to reuse the same clock
    ts = _now()
    entry_hash = _hash(
        prev_hash, timestamp=ts, operator_id=operator_id, device_id=device_id,
        checkout_id=checkout_id, action=action, severity=severity, detail=detail,
    )
    entry = AuditLog(
        timestamp=ts, operator_id=operator_id, device_id=device_id,
        checkout_id=checkout_id, action=action, severity=severity, detail=detail,
        prev_hash=prev_hash, entry_hash=entry_hash,
    )
    session.add(entry)
    session.flush()
    return entry


def verify_chain(session: Session) -> bool:
    """Return True iff every entry links correctly and no content was altered."""
    entries = session.execute(select(AuditLog).order_by(AuditLog.seq.asc())).scalars().all()
    prev_hash = GENESIS
    for e in entries:
        if e.prev_hash != prev_hash:
            return False
        recomputed = _hash(
            prev_hash, timestamp=e.timestamp, operator_id=e.operator_id,
            device_id=e.device_id, checkout_id=e.checkout_id, action=e.action,
            severity=e.severity, detail=e.detail,
        )
        if recomputed != e.entry_hash:
            return False
        prev_hash = e.entry_hash
    return True
