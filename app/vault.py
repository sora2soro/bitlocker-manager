"""Vault operations — the M1 service logic the API (M2) and agent will call.

Enforces the key-lifecycle rules from the spec:
* FR6/FR7  enrol & backfill, attributed to an operator (created_by).
* SR2      plaintext leaves the vault only via provisioning or SR9 reveal.
* SR4      rotation never overwrites — it revokes the old row and inserts a new one.
* SR8      every operation writes a hash-chained audit entry.
* SR9      reveal is Super-Admin only, high-severity logged, and flags rotation.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import append_audit
from .crypto import KekProvider, decrypt_key_material, encrypt_key_material
from .models import Device, KeyVersion, Operator, _now


class AuthorizationError(Exception):
    """Raised when an operator lacks the role for an action (SR7)."""


def enroll_key(session: Session, *, device: Device, key_material: str,
               operator: Operator, kek: KekProvider, key_type: str = "recovery",
               key_identifier: str | None = None, source: str = "setup") -> KeyVersion:
    """Store a new active key for a device, attributed to ``operator`` (FR7)."""
    encrypted_material, wrapped_dek = encrypt_key_material(key_material, kek)
    kv = KeyVersion(
        device_id=device.id, key_type=key_type, key_identifier=key_identifier,
        encrypted_material=encrypted_material, wrapped_dek=wrapped_dek,
        status="active", source=source, created_by=operator.id,
    )
    session.add(kv)
    session.flush()
    append_audit(session, action="key_enrolled", operator_id=operator.id,
                 device_id=device.id, detail=f"source={source} type={key_type}")
    return kv


def backfill_key(session: Session, *, device: Device, key_material: str,
                 operator: Operator, kek: KekProvider,
                 key_identifier: str | None = None) -> KeyVersion:
    """Capture the existing key of an already-encrypted machine (FR6)."""
    return enroll_key(session, device=device, key_material=key_material,
                      operator=operator, kek=kek, key_identifier=key_identifier,
                      source="backfill")


def active_key(session: Session, device: Device) -> KeyVersion | None:
    return session.execute(
        select(KeyVersion).where(
            KeyVersion.device_id == device.id, KeyVersion.status == "active"
        )
    ).scalar_one_or_none()


def get_key_for_provisioning(session: Session, *, device: Device, operator: Operator,
                             kek: KekProvider) -> str:
    """Decrypt the active key for USB provisioning. Plaintext stays in memory."""
    kv = active_key(session, device)
    if kv is None:
        raise LookupError(f"no active key for device {device.hostname}")
    material = decrypt_key_material(kv.encrypted_material, kv.wrapped_dek, kek)
    append_audit(session, action="key_provisioned", operator_id=operator.id,
                 device_id=device.id)
    return material


def rotate_key(session: Session, *, device: Device, new_key_material: str,
               operator: Operator, kek: KekProvider,
               new_key_identifier: str | None = None) -> KeyVersion:
    """Revoke the current key and insert a fresh active one (SR4). Never overwrites."""
    current = active_key(session, device)
    encrypted_material, wrapped_dek = encrypt_key_material(new_key_material, kek)
    new_kv = KeyVersion(
        device_id=device.id, key_type="recovery", key_identifier=new_key_identifier,
        encrypted_material=encrypted_material, wrapped_dek=wrapped_dek,
        status="active", source="rotation",
        rotated_from=current.id if current else None, created_by=operator.id,
    )
    if current is not None:
        current.status = "revoked"
        current.revoked_at = _now()
    session.add(new_kv)
    session.flush()
    append_audit(session, action="key_rotated", operator_id=operator.id,
                 device_id=device.id,
                 detail=f"rotated_from={current.id if current else None}")
    return new_kv


def reveal_key(session: Session, *, device: Device, operator: Operator,
               reason: str, kek: KekProvider) -> str:
    """Break-glass plaintext reveal (SR9).

    Super-Admin only; requires a reason; logged high-severity; flags the key for
    mandatory rotation (a seen key is a burned key). Step-up MFA is enforced at
    the API layer (M2) before this is reached.
    """
    if operator.role != "super_admin":
        raise AuthorizationError("break-glass reveal requires the super_admin role")
    if not reason or not reason.strip():
        raise ValueError("reveal requires a reason")
    kv = active_key(session, device)
    if kv is None:
        raise LookupError(f"no active key for device {device.hostname}")
    material = decrypt_key_material(kv.encrypted_material, kv.wrapped_dek, kek)
    append_audit(session, action="key_revealed_breakglass", severity="high",
                 operator_id=operator.id, device_id=device.id,
                 detail=f"reason={reason.strip()} rotation=pending")
    return material
