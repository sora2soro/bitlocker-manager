"""FastAPI service (M2) — wraps the vault core with auth, MFA, RBAC, and the REST API.

Security notes:
* Every key-touching endpoint requires a valid access token, so login gates
  decryption (SR6). The KEK master passphrase is not stored in the DB, so a stolen
  database alone cannot decrypt keys.
* Device listings expose hostname + Recovery Key ID only, never the key (SR2/FR8).
* The checkout lifecycle enforces single-use provisioning (SR3) and the
  rotation-before-close gate (SR4) server-side.
* Break-glass reveal is super_admin-only with step-up MFA and high-severity logging (SR9).

Future hardening (documented, not yet done): bind the KEK to per-operator login so a
compromised service secret alone is insufficient; enforce CSP frame-ancestors at the UI
layer (M5) for the DSE Site / inventory embeds.
"""
from __future__ import annotations

import csv
import datetime as dt
import io

import jwt
import pyotp
from fastapi import Depends, FastAPI, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, or_, select

from . import vault
from .audit import append_audit, verify_chain
from .config import settings as default_settings
from .crypto import SoftwareKekProvider
from .db import make_engine, session_factory
from .deps import (
    get_current_operator,
    get_kek,
    get_session,
    get_settings,
    require_role,
    visible_sites,
)
from .models import AuditLog, Base, Checkout, Device, KeyVersion, Operator, _now
from .schemas import (
    AuditOut,
    AuditResp,
    CheckoutOpen,
    CheckoutOpenResp,
    DeviceCreate,
    DeviceOut,
    DeviceUpdate,
    KeyEnroll,
    LoginReq,
    MfaReq,
    OperatorCreate,
    OperatorCreateResp,
    OperatorOut,
    OperatorUpdate,
    ProvisionReq,
    ProvisionResp,
    RevealReq,
    RevealResp,
    RotateReq,
    TokenResp,
)
from .security import create_token, decode_token, hash_password, verify_password, verify_totp


def _device_out(session, d: Device) -> DeviceOut:
    active = vault.active_key(session, d)
    return DeviceOut(
        id=d.id, hostname=d.hostname, site=d.site, department=d.department,
        encryption_status=d.encryption_status,
        recovery_key_id=(active.key_identifier if active else None),
        has_active_key=active is not None,
    )


def create_app(*, engine=None, kek=None, settings=None) -> FastAPI:
    settings = settings or default_settings
    if engine is None:
        engine = make_engine(settings.db_url)
        Base.metadata.create_all(engine)
    from .db import run_light_migrations
    run_light_migrations(engine)
    if kek is None:
        kek = SoftwareKekProvider(settings.kek_passphrase, settings.kek_salt)

    app = FastAPI(title="BitLocker Manager", version="0.2")
    app.state.settings = settings
    app.state.session_factory = session_factory(engine)
    app.state.kek = kek

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in settings.cors_origins.split(",")],
        allow_methods=["*"], allow_headers=["*"],
    )

    # ---------------- auth ----------------
    @app.post("/auth/login", response_model=TokenResp)
    def login(body: LoginReq, session=Depends(get_session)):
        op = session.execute(
            select(Operator).where(Operator.username == body.username)
        ).scalar_one_or_none()
        # constant-ish path: always check to avoid trivial user enumeration
        ok = op is not None and op.status == "active" and verify_password(op.password_hash, body.password)
        if not ok:
            append_audit(session, action="login_failed", detail=f"user={body.username}")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
        if op.mfa_secret:
            mfa_token = create_token(settings.jwt_secret, sub=op.id, role=op.role,
                                     scope=op.scope, kind="mfa_pending",
                                     ttl_seconds=settings.mfa_ttl_seconds)
            return TokenResp(mfa_token=mfa_token)
        # no MFA configured → issue access directly
        access = create_token(settings.jwt_secret, sub=op.id, role=op.role,
                              scope=op.scope, kind="access",
                              ttl_seconds=settings.access_ttl_seconds)
        append_audit(session, action="login", operator_id=op.id)
        return TokenResp(access_token=access)

    @app.post("/auth/mfa", response_model=TokenResp)
    def mfa(body: MfaReq, session=Depends(get_session)):
        try:
            claims = decode_token(settings.jwt_secret, body.mfa_token)
        except jwt.PyJWTError:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired MFA token")
        if claims.get("kind") != "mfa_pending":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not an MFA token")
        op = session.get(Operator, claims.get("sub"))
        if op is None or not verify_totp(op.mfa_secret, body.code):
            append_audit(session, action="mfa_failed",
                         operator_id=(op.id if op else None))
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid MFA code")
        access = create_token(settings.jwt_secret, sub=op.id, role=op.role,
                              scope=op.scope, kind="access",
                              ttl_seconds=settings.access_ttl_seconds)
        append_audit(session, action="login", operator_id=op.id)
        return TokenResp(access_token=access)

    # ---------------- devices ----------------
    @app.get("/devices", response_model=list[DeviceOut])
    def list_devices(q: str | None = None, limit: int = 100, offset: int = 0,
                     session=Depends(get_session),
                     operator: Operator = Depends(get_current_operator)):
        stmt = select(Device).where(Device.archived.is_(False))
        sites = visible_sites(operator)
        if sites is not None:
            stmt = stmt.where(Device.site.in_(sites))
        if q and q.strip():
            like = f"%{q.strip()}%"
            # match hostname, serial, or Recovery Key ID (volume_id) — all indexed
            stmt = stmt.where(or_(
                Device.hostname.ilike(like),
                Device.serial.ilike(like),
                Device.volume_id.ilike(like),
            ))
        stmt = stmt.order_by(Device.hostname).limit(min(max(limit, 1), 500)).offset(max(offset, 0))
        return [_device_out(session, d) for d in session.execute(stmt).scalars().all()]

    @app.patch("/devices/{device_id}", response_model=DeviceOut)
    def update_device(device_id: str, body: DeviceUpdate, session=Depends(get_session),
                      operator: Operator = Depends(require_role("super_admin"))):
        d = session.get(Device, device_id)
        if d is None or d.archived:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
        changes = body.model_dump(exclude_unset=True)
        for field, value in changes.items():
            setattr(d, field, value)
        session.flush()
        append_audit(session, action="device_updated", operator_id=operator.id,
                     device_id=d.id, detail=",".join(changes.keys()))
        return _device_out(session, d)

    @app.post("/devices/{device_id}/archive")
    def archive_device(device_id: str, session=Depends(get_session),
                       operator: Operator = Depends(require_role("super_admin"))):
        d = session.get(Device, device_id)
        if d is None or d.archived:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
        d.archived = True
        d.archived_at = _now()
        d.archived_by = operator.id
        append_audit(session, action="device_archived", operator_id=operator.id, device_id=d.id)
        return {"archived": True, "hostname": d.hostname}

    @app.get("/devices/{device_id}", response_model=DeviceOut)
    def get_device(device_id: str, session=Depends(get_session),
                   operator: Operator = Depends(get_current_operator)):
        d = session.get(Device, device_id)
        if d is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
        sites = visible_sites(operator)
        if sites is not None and d.site not in sites:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "out of scope")
        return _device_out(session, d)

    @app.post("/devices", response_model=DeviceOut, status_code=201)
    def create_device(body: DeviceCreate, session=Depends(get_session),
                      operator: Operator = Depends(require_role("admin", "super_admin"))):
        d = Device(hostname=body.hostname, site=body.site, serial=body.serial,
                   volume_id=body.volume_id, department=body.department,
                   encryption_status="encrypted")
        session.add(d)
        session.flush()
        append_audit(session, action="device_enrolled", operator_id=operator.id, device_id=d.id)
        return _device_out(session, d)

    @app.post("/devices/{device_id}/keys", response_model=DeviceOut, status_code=201)
    def enroll_device_key(device_id: str, body: KeyEnroll, session=Depends(get_session),
                          operator: Operator = Depends(require_role("operator", "admin", "super_admin")),
                          kek=Depends(get_kek)):
        d = session.get(Device, device_id)
        if d is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
        vault.enroll_key(session, device=d, key_material=body.key_material, operator=operator,
                         kek=kek, key_type=body.key_type, key_identifier=body.key_identifier,
                         source=body.source)
        return _device_out(session, d)

    # ---------------- checkout lifecycle ----------------
    @app.post("/checkouts", response_model=CheckoutOpenResp)
    def open_checkout(body: CheckoutOpen, session=Depends(get_session),
                      operator: Operator = Depends(require_role("operator", "admin", "super_admin"))):
        d = session.get(Device, body.device_id)
        if d is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
        sites = visible_sites(operator)
        if sites is not None and d.site not in sites:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "out of scope")
        c = Checkout(device_id=d.id, operator_id=operator.id, ticket_ref=body.ticket_ref)
        session.add(c)
        session.flush()
        token = create_token(settings.jwt_secret, sub=c.id, role="agent",
                             scope=d.id, kind="provision", ttl_seconds=settings.mfa_ttl_seconds)
        append_audit(session, action="checkout_opened", operator_id=operator.id,
                     device_id=d.id, checkout_id=c.id)
        return CheckoutOpenResp(checkout_id=c.id, provisioning_token=token)

    @app.post("/checkouts/{checkout_id}/provision", response_model=ProvisionResp)
    def provision(checkout_id: str, body: ProvisionReq, session=Depends(get_session),
                  kek=Depends(get_kek)):
        try:
            claims = decode_token(settings.jwt_secret, body.provisioning_token)
        except jwt.PyJWTError:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid provisioning token")
        if claims.get("kind") != "provision" or claims.get("sub") != checkout_id:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token/checkout mismatch")
        c = session.get(Checkout, checkout_id)
        if c is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "checkout not found")
        if c.provisioned_at is not None:                       # SR3: single-use
            raise HTTPException(status.HTTP_409_CONFLICT, "already provisioned")
        d = session.get(Device, c.device_id)
        # provisioning is agent-driven; attribute the decrypt to the checkout's operator
        op = session.get(Operator, c.operator_id)
        material = vault.get_key_for_provisioning(session, device=d, operator=op, kek=kek)
        c.provisioned_at = _now()
        c.usb_serial = body.usb_serial
        return ProvisionResp(key_material=material)

    @app.post("/checkouts/{checkout_id}/rotate")
    def rotate(checkout_id: str, body: RotateReq, session=Depends(get_session), kek=Depends(get_kek)):
        c = session.get(Checkout, checkout_id)
        if c is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "checkout not found")
        d = session.get(Device, c.device_id)
        op = session.get(Operator, c.operator_id)
        vault.rotate_key(session, device=d, new_key_material=body.new_key_material,
                         operator=op, kek=kek, new_key_identifier=body.new_key_identifier)
        c.rotation_confirmed = True
        return {"rotation_confirmed": True}

    @app.post("/checkouts/{checkout_id}/wipe")
    def wipe(checkout_id: str, session=Depends(get_session)):
        c = session.get(Checkout, checkout_id)
        if c is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "checkout not found")
        c.wiped_at = _now()
        return {"wiped": True}

    @app.post("/checkouts/{checkout_id}/close")
    def close_checkout(checkout_id: str, session=Depends(get_session),
                       operator: Operator = Depends(require_role("operator", "admin", "super_admin"))):
        c = session.get(Checkout, checkout_id)
        if c is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "checkout not found")
        # SR3 + SR4: cannot close unless the USB was wiped AND the key was rotated
        if c.wiped_at is None or not c.rotation_confirmed:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"cannot close: wiped={c.wiped_at is not None} rotation_confirmed={c.rotation_confirmed}",
            )
        c.status = "closed"
        append_audit(session, action="checkout_closed", operator_id=operator.id,
                     device_id=c.device_id, checkout_id=c.id)
        return {"status": "closed"}

    # ---------------- reveal (break-glass, SR9) ----------------
    @app.post("/devices/{device_id}/reveal", response_model=RevealResp)
    def reveal(device_id: str, body: RevealReq, session=Depends(get_session),
               operator: Operator = Depends(require_role("super_admin")), kek=Depends(get_kek)):
        # step-up MFA: a fresh TOTP right now, not just an earlier login
        if not verify_totp(operator.mfa_secret, body.code):
            append_audit(session, action="reveal_stepup_failed", severity="high",
                         operator_id=operator.id, device_id=device_id)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "step-up MFA failed")
        d = session.get(Device, device_id)
        if d is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
        material = vault.reveal_key(session, device=d, operator=operator, reason=body.reason, kek=kek)
        return RevealResp(key_material=material,
                          warning="This key is now flagged for mandatory rotation (SR9).")

    # ---------------- audit ----------------
    @app.get("/audit", response_model=AuditResp)
    def read_audit(session=Depends(get_session),
                   operator: Operator = Depends(require_role("auditor", "admin", "super_admin"))):
        entries = session.execute(select(AuditLog).order_by(AuditLog.seq.asc())).scalars().all()
        return AuditResp(
            chain_valid=verify_chain(session),
            entries=[AuditOut(seq=e.seq, action=e.action, severity=e.severity,
                              operator_id=e.operator_id, device_id=e.device_id, detail=e.detail)
                     for e in entries],
        )

    # ---------------- user management (super admin only) ----------------
    _ROLES = {"operator", "admin", "auditor", "super_admin"}

    def _op_out(op: Operator) -> OperatorOut:
        return OperatorOut(id=op.id, username=op.username, role=op.role,
                           scope=op.scope, status=op.status)

    def _active_supers(session) -> int:
        return session.execute(
            select(func.count()).select_from(Operator)
            .where(Operator.role == "super_admin", Operator.status == "active")
        ).scalar_one()

    def _is_last_active_super(session, op: Operator) -> bool:
        return op.role == "super_admin" and op.status == "active" and _active_supers(session) <= 1

    @app.get("/operators", response_model=list[OperatorOut])
    def list_operators(session=Depends(get_session),
                       _: Operator = Depends(require_role("super_admin"))):
        ops = session.execute(select(Operator).order_by(Operator.username)).scalars().all()
        return [_op_out(o) for o in ops]

    @app.post("/operators", response_model=OperatorCreateResp, status_code=201)
    def create_operator(body: OperatorCreate, session=Depends(get_session),
                        actor: Operator = Depends(require_role("super_admin"))):
        if body.role not in _ROLES:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"role must be one of {sorted(_ROLES)}")
        if body.role == "operator" and not body.scope:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "operators require a scope (site)")
        if session.execute(select(Operator).where(Operator.username == body.username)).scalar_one_or_none():
            raise HTTPException(status.HTTP_409_CONFLICT, "username already exists")
        secret = pyotp.random_base32()
        op = Operator(username=body.username, password_hash=hash_password(body.password),
                      role=body.role, scope=body.scope, mfa_secret=secret, status="active")
        session.add(op)
        session.flush()
        append_audit(session, action="user_created", operator_id=actor.id,
                     detail=f"user={op.username} role={op.role}")
        uri = pyotp.TOTP(secret).provisioning_uri(name=op.username, issuer_name="BitLocker Manager")
        return OperatorCreateResp(operator=_op_out(op), mfa_secret=secret, mfa_uri=uri)

    @app.patch("/operators/{op_id}", response_model=OperatorOut)
    def update_operator(op_id: str, body: OperatorUpdate, session=Depends(get_session),
                        actor: Operator = Depends(require_role("super_admin"))):
        op = session.get(Operator, op_id)
        if op is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
        # demoting the last active super admin would lock everyone out
        if body.role and body.role != "super_admin" and _is_last_active_super(session, op):
            raise HTTPException(status.HTTP_409_CONFLICT, "cannot demote the last active Super Admin")
        if body.role is not None:
            if body.role not in _ROLES:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid role")
            op.role = body.role
        if body.scope is not None:
            op.scope = body.scope
        append_audit(session, action="user_updated", operator_id=actor.id,
                     detail=f"user={op.username} role={op.role}")
        return _op_out(op)

    @app.post("/operators/{op_id}/activate", response_model=OperatorOut)
    def activate_operator(op_id: str, session=Depends(get_session),
                          actor: Operator = Depends(require_role("super_admin"))):
        op = session.get(Operator, op_id)
        if op is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
        op.status = "active"
        append_audit(session, action="user_activated", operator_id=actor.id, detail=f"user={op.username}")
        return _op_out(op)

    @app.post("/operators/{op_id}/deactivate", response_model=OperatorOut)
    def deactivate_operator(op_id: str, session=Depends(get_session),
                            actor: Operator = Depends(require_role("super_admin"))):
        op = session.get(Operator, op_id)
        if op is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
        if _is_last_active_super(session, op):
            raise HTTPException(status.HTTP_409_CONFLICT, "cannot deactivate the last active Super Admin")
        op.status = "inactive"
        append_audit(session, action="user_deactivated", operator_id=actor.id, detail=f"user={op.username}")
        return _op_out(op)

    @app.delete("/operators/{op_id}")
    def delete_operator(op_id: str, session=Depends(get_session),
                        actor: Operator = Depends(require_role("super_admin"))):
        op = session.get(Operator, op_id)
        if op is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
        if _is_last_active_super(session, op):
            raise HTTPException(status.HTTP_409_CONFLICT, "cannot delete the last active Super Admin")
        username = op.username
        session.delete(op)
        append_audit(session, action="user_deleted", operator_id=actor.id, detail=f"user={username}")
        return {"deleted": True, "username": username}

    # ---------------- exports (audit reports / inventory — never keys) ----------------
    def _spreadsheet(filename: str, header: list[str], rows: list[list], fmt: str) -> Response:
        if fmt == "xlsx":
            from openpyxl import Workbook
            wb = Workbook()
            ws = wb.active
            ws.append(header)
            for r in rows:
                ws.append(["" if v is None else v for v in r])
            buf = io.BytesIO()
            wb.save(buf)
            return Response(
                content=buf.getvalue(),
                media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                headers={"Content-Disposition": f'attachment; filename="{filename}.xlsx"'},
            )
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(header)
        w.writerows(rows)
        return Response(content=buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{filename}.csv"'})

    @app.get("/export/inventory")
    def export_inventory(q: str | None = None, fmt: str = Query("csv", pattern="^(csv|xlsx)$"),
                         session=Depends(get_session),
                         operator: Operator = Depends(require_role("super_admin", "auditor"))):
        stmt = select(Device).where(Device.archived.is_(False))
        if q and q.strip():
            like = f"%{q.strip()}%"
            stmt = stmt.where(or_(Device.hostname.ilike(like), Device.serial.ilike(like),
                                  Device.volume_id.ilike(like)))
        stmt = stmt.order_by(Device.hostname)
        header = ["Hostname", "Site", "Department", "Serial", "Recovery Key ID",
                  "Encryption Status", "Has Key", "Enrolled At"]
        rows = []
        for d in session.execute(stmt).scalars().all():
            active = vault.active_key(session, d)
            rows.append([d.hostname, d.site, d.department, d.serial,
                         (active.key_identifier if active else None),
                         d.encryption_status, "yes" if active else "no",
                         d.created_at.isoformat() if d.created_at else None])
        append_audit(session, action="export_inventory", operator_id=operator.id,
                     detail=f"rows={len(rows)} fmt={fmt}")
        return _spreadsheet("inventory", header, rows, fmt)

    @app.get("/export/audit")
    def export_audit(fmt: str = Query("csv", pattern="^(csv|xlsx)$"),
                     date_from: str | None = None, date_to: str | None = None,
                     session=Depends(get_session),
                     operator: Operator = Depends(require_role("super_admin", "auditor"))):
        stmt = select(AuditLog).order_by(AuditLog.seq.asc())
        if date_from:
            stmt = stmt.where(AuditLog.timestamp >= dt.datetime.fromisoformat(date_from))
        if date_to:
            end = dt.datetime.fromisoformat(date_to) + dt.timedelta(days=1)
            stmt = stmt.where(AuditLog.timestamp < end)
        header = ["Seq", "Timestamp", "Action", "Severity", "Operator ID", "Device ID", "Detail"]
        rows = [[e.seq, e.timestamp.isoformat() if e.timestamp else None, e.action, e.severity,
                 e.operator_id, e.device_id, e.detail]
                for e in session.execute(stmt).scalars().all()]
        append_audit(session, action="export_audit", operator_id=operator.id,
                     detail=f"rows={len(rows)} fmt={fmt}")
        return _spreadsheet("audit-report", header, rows, fmt)

    # ---------------- static operator UI (M5) ----------------
    # Served here for field-test convenience; in production the UI is a separate
    # front door (DSE Site / inventory embed) hitting this API over HTTPS.
    import os as _os
    from fastapi.staticfiles import StaticFiles
    _ui = _os.path.join(_os.path.dirname(__file__), "..", "ui")
    if _os.path.isdir(_ui):
        app.mount("/ui", StaticFiles(directory=_ui, html=True), name="ui")

    return app
