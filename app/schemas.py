"""API schemas (spec §6). Note: no schema ever returns stored key material except
the explicit provisioning/reveal responses.
"""
from __future__ import annotations

from pydantic import BaseModel


# ---- auth ----
class LoginReq(BaseModel):
    username: str
    password: str


class MfaReq(BaseModel):
    mfa_token: str
    code: str


class TokenResp(BaseModel):
    access_token: str | None = None
    mfa_token: str | None = None
    token_type: str = "bearer"


# ---- sites (pick-list) ----
class SiteCreate(BaseModel):
    name: str
    code: str | None = None


class SiteOut(BaseModel):
    id: str
    name: str
    code: str | None
    is_active: bool


# ---- devices ----
class DeviceCreate(BaseModel):
    hostname: str
    site: str
    serial: str | None = None
    volume_id: str | None = None
    department: str | None = None


class DeviceUpdate(BaseModel):
    hostname: str | None = None
    site: str | None = None
    department: str | None = None
    serial: str | None = None


class KeyEnroll(BaseModel):
    key_material: str
    key_identifier: str | None = None
    key_type: str = "recovery"
    source: str = "setup"          # setup | backfill


class DeviceOut(BaseModel):
    id: str
    hostname: str
    site: str
    department: str | None
    serial: str | None
    encryption_status: str
    recovery_key_id: str | None    # the on-screen lookup handle — NOT the key
    has_active_key: bool


class ImportRow(BaseModel):
    hostname: str
    site: str
    key_identifier: str
    key_material: str
    serial: str | None = None


class ImportResp(BaseModel):
    created: int
    skipped: int
    errors: list[str]


# ---- data quality (sanitation) ----
class IncompleteDeviceOut(BaseModel):
    id: str
    hostname: str
    site: str
    serial: str | None
    recovery_key_id: str | None
    missing: list[str]              # which fields are blank: 'hostname' | 'serial' | 'recovery_key_id'


class DataQualityResp(BaseModel):
    total: int                     # non-archived devices scanned
    incomplete: int                # how many have at least one gap
    missing_serial: int
    missing_hostname: int
    missing_recovery_key_id: int
    devices: list[IncompleteDeviceOut]


# ---- checkouts ----
class CheckoutOpen(BaseModel):
    device_id: str
    ticket_ref: str | None = None


class CheckoutOpenResp(BaseModel):
    checkout_id: str
    provisioning_token: str        # single-use, for the agent


class ProvisionReq(BaseModel):
    provisioning_token: str
    usb_serial: str


class ProvisionResp(BaseModel):
    key_material: str              # written to the USB by the agent, never shown to a human


class RotateReq(BaseModel):
    new_key_material: str
    new_key_identifier: str | None = None


# ---- reveal ----
class RevealReq(BaseModel):
    code: str                      # step-up MFA (fresh TOTP)
    reason: str


class RevealResp(BaseModel):
    key_material: str
    warning: str


# ---- audit ----
class AuditOut(BaseModel):
    seq: int
    action: str
    severity: str
    operator_id: str | None
    device_id: str | None
    detail: str | None


class AuditResp(BaseModel):
    chain_valid: bool
    entries: list[AuditOut]


# ---- operators (user management, super admin only) ----
class OperatorCreate(BaseModel):
    username: str
    password: str
    role: str                      # operator | admin | auditor | super_admin
    scope: str | None = None       # required for role=operator
    first_name: str | None = None
    last_name: str | None = None
    middle_initial: str | None = None
    job_title: str | None = None


class OperatorUpdate(BaseModel):
    role: str | None = None
    scope: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    middle_initial: str | None = None
    job_title: str | None = None


class OperatorOut(BaseModel):
    id: str
    username: str
    role: str
    scope: str | None
    status: str
    first_name: str | None = None
    last_name: str | None = None
    middle_initial: str | None = None
    job_title: str | None = None
    display_name: str | None = None   # "Last, First M." convenience for the UI


class OperatorCreateResp(BaseModel):
    operator: OperatorOut
    mfa_secret: str
    mfa_uri: str                   # otpauth:// for the QR
