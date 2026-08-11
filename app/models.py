"""Data model (spec §5). SQLAlchemy 2.0 declarative."""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Base(DeclarativeBase):
    pass


class Site(Base):
    """A physical site/campaign that populates the Site/Scope dropdowns.

    Device.site and Operator.scope store the site *name* (not a FK) so existing
    rows and the whole codebase keep working unchanged; this table is the
    authoritative source for the pick-lists and lets Admins add new sites.
    """
    __tablename__ = "sites"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    code: Mapped[str | None] = mapped_column(String(16), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str | None] = mapped_column(ForeignKey("operators.id"), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    serial: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    volume_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    site: Mapped[str] = mapped_column(String(64), index=True)
    department: Mapped[str | None] = mapped_column(String(128), nullable=True)
    encryption_status: Mapped[str] = mapped_column(String(32), default="unknown")
    archived: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    archived_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_by: Mapped[str | None] = mapped_column(ForeignKey("operators.id"), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    key_versions: Mapped[list["KeyVersion"]] = relationship(back_populates="device")


class Operator(Base):
    __tablename__ = "operators"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    # profile (FR: identify the human behind the account)
    first_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    middle_initial: Mapped[str | None] = mapped_column(String(4), nullable=True)
    job_title: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # operator | admin | auditor | super_admin
    role: Mapped[str] = mapped_column(String(32))
    scope: Mapped[str | None] = mapped_column(String(64), nullable=True)  # site scope; null = all
    mfa_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active")


class KeyVersion(Base):
    __tablename__ = "key_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    key_type: Mapped[str] = mapped_column(String(16))            # recovery | startup
    key_identifier: Mapped[str | None] = mapped_column(String(64), nullable=True)  # recovery key ID GUID
    encrypted_material: Mapped[bytes] = mapped_column(LargeBinary)   # nonce || ciphertext || tag
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary)          # nonce || ciphertext || tag
    status: Mapped[str] = mapped_column(String(16), default="active")   # active | revoked
    source: Mapped[str] = mapped_column(String(16), default="setup")    # setup | backfill | rotation
    rotated_from: Mapped[str | None] = mapped_column(ForeignKey("key_versions.id"), nullable=True)
    created_by: Mapped[str | None] = mapped_column(ForeignKey("operators.id"), nullable=True)  # FR7
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    device: Mapped["Device"] = relationship(back_populates="key_versions")


class Checkout(Base):
    __tablename__ = "checkouts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"))
    operator_id: Mapped[str] = mapped_column(ForeignKey("operators.id"))
    ticket_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    usb_serial: Mapped[str | None] = mapped_column(String(128), nullable=True)
    provisioned_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    unlocked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    wiped_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rotation_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(16), default="open")   # open | closed
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AuditLog(Base):
    """Append-only, hash-chained (SR8). ``seq`` orders the chain."""
    __tablename__ = "audit_log"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    operator_id: Mapped[str | None] = mapped_column(ForeignKey("operators.id"), nullable=True)
    device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    checkout_id: Mapped[str | None] = mapped_column(ForeignKey("checkouts.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16), default="info")   # info | high
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))
