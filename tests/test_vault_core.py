"""Vault-core tests. Each maps to a security requirement in the spec."""
import os

import pytest
from cryptography.exceptions import InvalidTag

from app.audit import append_audit, verify_chain
from app.crypto import (
    SoftwareKekProvider,
    decrypt_key_material,
    encrypt_key_material,
)
from app.db import make_memory_engine, session_factory
from app.models import Device, Operator
from app.vault import (
    AuthorizationError,
    active_key,
    enroll_key,
    get_key_for_provisioning,
    reveal_key,
    rotate_key,
)

RECOVERY_KEY = "123456-654321-111111-222222-333333-444444-555555-666666"
RECOVERY_KEY_2 = "999999-888888-777777-666666-555555-444444-333333-222222"


@pytest.fixture
def kek():
    return SoftwareKekProvider(passphrase=b"correct horse battery staple",
                               salt=b"sixteen-byte-salt!!")


@pytest.fixture
def session():
    s = session_factory(make_memory_engine())()
    yield s
    s.close()


@pytest.fixture
def seed(session):
    device = Device(hostname="DSE-FIL-042", site="Filandia",
                    volume_id="F70F2436-E285-40B3-AB51-B50CBF6EC24C")
    op = Operator(username="cris", password_hash="x", role="operator", scope="Filandia")
    admin = Operator(username="root", password_hash="x", role="super_admin")
    session.add_all([device, op, admin])
    session.flush()
    return device, op, admin


# ---- SR1: no plaintext at rest, authenticated encryption ----

def test_encrypt_roundtrip(kek):
    enc, wrapped = encrypt_key_material(RECOVERY_KEY, kek)
    assert RECOVERY_KEY.encode() not in enc        # plaintext not present in ciphertext
    assert decrypt_key_material(enc, wrapped, kek) == RECOVERY_KEY


def test_tamper_is_detected(kek):
    enc, wrapped = encrypt_key_material(RECOVERY_KEY, kek)
    tampered = bytearray(enc)
    tampered[-1] ^= 0x01
    with pytest.raises(InvalidTag):
        decrypt_key_material(bytes(tampered), wrapped, kek)


def test_wrong_kek_fails(kek):
    enc, wrapped = encrypt_key_material(RECOVERY_KEY, kek)
    other = SoftwareKekProvider(passphrase=b"a different passphrase",
                                salt=b"sixteen-byte-salt!!")
    with pytest.raises(InvalidTag):
        decrypt_key_material(enc, wrapped, other)


# ---- FR6/FR7 + SR2: enrol, attribute, provision ----

def test_enroll_and_provision(session, seed, kek):
    device, op, _ = seed
    kv = enroll_key(session, device=device, key_material=RECOVERY_KEY,
                    operator=op, kek=kek,
                    key_identifier=device.volume_id)
    assert kv.status == "active"
    assert kv.created_by == op.id           # FR7 accountability
    assert kv.source == "setup"
    got = get_key_for_provisioning(session, device=device, operator=op, kek=kek)
    assert got == RECOVERY_KEY              # SR2: decrypts only for provisioning


# ---- SR4: rotation never overwrites ----

def test_rotation_versions_never_overwrite(session, seed, kek):
    device, op, _ = seed
    v1 = enroll_key(session, device=device, key_material=RECOVERY_KEY,
                    operator=op, kek=kek)
    v2 = rotate_key(session, device=device, new_key_material=RECOVERY_KEY_2,
                    operator=op, kek=kek)
    session.refresh(v1)
    assert v1.status == "revoked" and v1.revoked_at is not None
    assert v2.status == "active"
    assert v2.rotated_from == v1.id                     # lineage preserved
    assert active_key(session, device).id == v2.id
    assert get_key_for_provisioning(session, device=device, operator=op, kek=kek) == RECOVERY_KEY_2


# ---- SR9: break-glass reveal is Super-Admin only, logged high-severity ----

def test_reveal_requires_super_admin(session, seed, kek):
    device, op, _ = seed
    enroll_key(session, device=device, key_material=RECOVERY_KEY, operator=op, kek=kek)
    with pytest.raises(AuthorizationError):
        reveal_key(session, device=device, operator=op, reason="troubleshoot", kek=kek)


def test_reveal_by_super_admin_logs_high(session, seed, kek):
    device, op, admin = seed
    enroll_key(session, device=device, key_material=RECOVERY_KEY, operator=op, kek=kek)
    material = reveal_key(session, device=device, operator=admin,
                          reason="USB path failed on DSE-FIL-042", kek=kek)
    assert material == RECOVERY_KEY
    from app.models import AuditLog
    from sqlalchemy import select
    high = session.execute(
        select(AuditLog).where(AuditLog.action == "key_revealed_breakglass")
    ).scalar_one()
    assert high.severity == "high"


def test_reveal_needs_reason(session, seed, kek):
    device, _, admin = seed
    enroll_key(session, device=device, key_material=RECOVERY_KEY, operator=admin, kek=kek)
    with pytest.raises(ValueError):
        reveal_key(session, device=device, operator=admin, reason="  ", kek=kek)


# ---- SR8: hash-chained audit log detects tampering ----

def test_audit_chain_valid_after_operations(session, seed, kek):
    device, op, _ = seed
    enroll_key(session, device=device, key_material=RECOVERY_KEY, operator=op, kek=kek)
    rotate_key(session, device=device, new_key_material=RECOVERY_KEY_2, operator=op, kek=kek)
    assert verify_chain(session) is True


def test_audit_chain_detects_tampering(session, seed):
    _, op, _ = seed
    append_audit(session, action="login", operator_id=op.id)
    e2 = append_audit(session, action="key_enrolled", operator_id=op.id)
    append_audit(session, action="logout", operator_id=op.id)
    assert verify_chain(session) is True
    e2.action = "nothing_to_see_here"      # tamper an entry's content
    session.flush()
    assert verify_chain(session) is False
