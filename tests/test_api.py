"""M2 API tests via FastAPI TestClient. Each maps to a requirement."""
import pyotp
import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.config import Settings
from app.crypto import SoftwareKekProvider
from app.db import make_memory_engine, session_factory
from app.models import Operator
from app.security import hash_password

RECOVERY_KEY = "123456-654321-111111-222222-333333-444444-555555-666666"
NEW_KEY = "999999-888888-777777-666666-555555-444444-333333-222222"
MFA_SECRET = pyotp.random_base32()


@pytest.fixture
def app_client():
    settings = Settings()
    engine = make_memory_engine()
    kek = SoftwareKekProvider(settings.kek_passphrase, settings.kek_salt)
    # seed operators
    s = session_factory(engine)()
    s.add_all([
        Operator(username="cris", password_hash=hash_password("pw-cris"),
                 role="operator", scope="Filandia", mfa_secret=MFA_SECRET),
        Operator(username="mat", password_hash=hash_password("pw-mat"),
                 role="operator", scope="Matina", mfa_secret=MFA_SECRET),
        Operator(username="boss", password_hash=hash_password("pw-boss"),
                 role="super_admin", mfa_secret=MFA_SECRET),
        Operator(username="admin", password_hash=hash_password("pw-admin"),
                 role="admin", mfa_secret=MFA_SECRET),
        Operator(username="auditor", password_hash=hash_password("pw-aud"),
                 role="auditor", mfa_secret=MFA_SECRET),
    ])
    s.commit()
    s.close()
    app = create_app(engine=engine, kek=kek, settings=settings)
    client = TestClient(app)
    client.engine = engine        # exposed so tests can seed rows the API won't create (e.g. a 2nd super)
    return client


def token_for(client, username, password):
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    mfa_token = r.json()["mfa_token"]
    code = pyotp.TOTP(MFA_SECRET).now()
    r = client.post("/auth/mfa", json={"mfa_token": mfa_token, "code": code})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def auth(tok):
    return {"Authorization": f"Bearer {tok}"}


# ---- SR6: auth + MFA ----

def test_login_requires_mfa_then_issues_access(app_client):
    r = app_client.post("/auth/login", json={"username": "cris", "password": "pw-cris"})
    assert r.status_code == 200 and r.json()["mfa_token"] and r.json()["access_token"] is None


def test_bad_password_rejected(app_client):
    r = app_client.post("/auth/login", json={"username": "cris", "password": "wrong"})
    assert r.status_code == 401


def test_bad_mfa_rejected(app_client):
    r = app_client.post("/auth/login", json={"username": "cris", "password": "pw-cris"})
    r = app_client.post("/auth/mfa", json={"mfa_token": r.json()["mfa_token"], "code": "000000"})
    assert r.status_code == 401


def test_no_token_is_401(app_client):
    assert app_client.get("/devices").status_code == 401


# ---- helpers to set up a device with a key ----

def _seed_device(client, admin_tok, op_tok, site="Filandia"):
    r = client.post("/devices", headers=auth(admin_tok),
                    json={"hostname": "DSE-FIL-042", "site": site,
                          "volume_id": "F70F2436-E285-40B3-AB51-B50CBF6EC24C"})
    assert r.status_code == 201, r.text
    dev_id = r.json()["id"]
    r = client.post(f"/devices/{dev_id}/keys", headers=auth(op_tok),
                    json={"key_material": RECOVERY_KEY,
                          "key_identifier": "F70F2436-E285-40B3-AB51-B50CBF6EC24C"})
    assert r.status_code == 201, r.text
    return dev_id


# ---- SR2/FR8: listing shows Key ID, never the key ----

def test_device_list_hides_key(app_client):
    admin = token_for(app_client, "admin", "pw-admin")
    cris = token_for(app_client, "cris", "pw-cris")
    _seed_device(app_client, admin, cris)
    r = app_client.get("/devices", headers=auth(cris))
    assert r.status_code == 200
    body = r.json()[0]
    assert body["recovery_key_id"] == "F70F2436-E285-40B3-AB51-B50CBF6EC24C"
    assert "key_material" not in body and RECOVERY_KEY not in r.text


# ---- SR5: scope — an operator sees only their site ----

def test_scope_isolates_sites(app_client):
    admin = token_for(app_client, "admin", "pw-admin")
    cris = token_for(app_client, "cris", "pw-cris")   # Filandia
    mat = token_for(app_client, "mat", "pw-mat")       # Matina
    _seed_device(app_client, admin, cris, site="Filandia")
    assert len(app_client.get("/devices", headers=auth(cris)).json()) == 1
    assert len(app_client.get("/devices", headers=auth(mat)).json()) == 0


def test_server_side_search(app_client):
    admin = token_for(app_client, "admin", "pw-admin")
    cris = token_for(app_client, "cris", "pw-cris")
    # a couple of devices in Filandia
    app_client.post("/devices", headers=auth(admin),
                    json={"hostname": "DSE-FIL-042", "site": "Filandia",
                          "volume_id": "F70F2436-E285-40B3-AB51-B50CBF6EC24C"})
    app_client.post("/devices", headers=auth(admin),
                    json={"hostname": "DSE-FIL-099", "site": "Filandia", "serial": "SN-XYZ-1"})
    # search by hostname fragment
    r = app_client.get("/devices?q=099", headers=auth(cris))
    assert len(r.json()) == 1 and r.json()[0]["hostname"] == "DSE-FIL-099"
    # search by Recovery Key ID fragment
    r = app_client.get("/devices?q=B50CBF6", headers=auth(cris))
    assert len(r.json()) == 1 and r.json()[0]["hostname"] == "DSE-FIL-042"
    # search by serial
    r = app_client.get("/devices?q=xyz", headers=auth(cris))
    assert len(r.json()) == 1 and r.json()[0]["hostname"] == "DSE-FIL-099"
    # blank query returns all in scope
    assert len(app_client.get("/devices?q=", headers=auth(cris)).json()) == 2


def test_operator_cannot_create_device(app_client):
    cris = token_for(app_client, "cris", "pw-cris")
    r = app_client.post("/devices", headers=auth(cris),
                        json={"hostname": "x", "site": "Filandia"})
    assert r.status_code == 403


# ---- Pass 1: CRUD (edit/archive) + export ----

def test_edit_device_super_only(app_client):
    admin = token_for(app_client, "admin", "pw-admin")
    boss = token_for(app_client, "boss", "pw-boss")
    cris = token_for(app_client, "cris", "pw-cris")
    dev = _seed_device(app_client, admin, cris)
    assert app_client.patch(f"/devices/{dev}", headers=auth(admin),
                            json={"department": "IT"}).status_code == 403
    r = app_client.patch(f"/devices/{dev}", headers=auth(boss),
                         json={"department": "IT", "site": "Matina"})
    assert r.status_code == 200 and r.json()["department"] == "IT" and r.json()["site"] == "Matina"


def test_archive_hides_device(app_client):
    admin = token_for(app_client, "admin", "pw-admin")
    boss = token_for(app_client, "boss", "pw-boss")
    cris = token_for(app_client, "cris", "pw-cris")
    dev = _seed_device(app_client, admin, cris)
    assert len(app_client.get("/devices", headers=auth(cris)).json()) == 1
    assert app_client.post(f"/devices/{dev}/archive", headers=auth(admin)).status_code == 403
    assert app_client.post(f"/devices/{dev}/archive", headers=auth(boss)).status_code == 200
    assert len(app_client.get("/devices", headers=auth(cris)).json()) == 0


def test_export_roles_and_no_keys(app_client):
    admin = token_for(app_client, "admin", "pw-admin")
    boss = token_for(app_client, "boss", "pw-boss")
    aud = token_for(app_client, "auditor", "pw-aud")
    cris = token_for(app_client, "cris", "pw-cris")
    _seed_device(app_client, admin, cris)
    assert app_client.get("/export/inventory", headers=auth(aud)).status_code == 200
    assert app_client.get("/export/inventory", headers=auth(boss)).status_code == 200
    assert app_client.get("/export/inventory", headers=auth(cris)).status_code == 403
    assert app_client.get("/export/inventory", headers=auth(admin)).status_code == 403
    r = app_client.get("/export/inventory?fmt=csv", headers=auth(aud))
    assert "text/csv" in r.headers["content-type"]
    assert "DSE-FIL-042" in r.text and RECOVERY_KEY not in r.text
    r = app_client.get("/export/audit?fmt=xlsx", headers=auth(boss))
    assert "spreadsheetml" in r.headers["content-type"]


# ---- Import: parsers + commit ----

def test_import_recovery_txt_parser():
    from app.importers import parse_recovery_txt
    body = ("BitLocker Drive Encryption recovery key\n\nIdentifier:\n\n"
            "\t0BCA25A7-DDF3-4E97-87F1-A643EB656942\n\nRecovery Key:\n\n"
            "\t335357-052701-573265-124388-247709-400708-532015-331848\n")
    fname = "BitLocker_Recovery_Key_0BCA25A7-DDF3-4E97-87F1-A643EB656942_1DR5GX3_MAT-LTP-016.TXT"
    r = parse_recovery_txt(body, filename=fname)
    assert r["key_identifier"] == "0BCA25A7-DDF3-4E97-87F1-A643EB656942"
    assert r["key_material"].startswith("335357-052701") and r["key_material"].count("-") == 7
    assert r["hostname"] == "MAT-LTP-016"
    assert r["site"] == "MAT"
    assert r["serial"] == "1DR5GX3"


def test_import_csv_parser_matches_columns():
    from app.importers import parse_csv
    csv_text = (
        "Hostname,Site,Identifier,Recovery Key,Serial\n"
        "MAT-LTP-016,MAT,0BCA25A7-DDF3-4E97-87F1-A643EB656942,335357-052701-573265-124388-247709-400708-532015-331848,1DR5GX3\n"
        "MAT-LTP-017,MAT,F70F2436-E285-40B3-AB51-B50CBF6EC24C,123456-654321-111111-222222-333333-444444-555555-666666,2ABCDEF\n"
        "BADROW,MAT,not-a-guid,not-a-key,\n"
    )
    rows, mapping, warnings = parse_csv(csv_text)
    assert len(rows) == 2
    assert rows[0]["hostname"] == "MAT-LTP-016"
    assert mapping["key_identifier"] == "Identifier"
    assert any("BADROW" in w for w in warnings)


def test_import_commit_admin_only_and_idempotent(app_client):
    admin = token_for(app_client, "admin", "pw-admin")
    cris = token_for(app_client, "cris", "pw-cris")
    payload = [
        {"hostname": "MAT-LTP-100", "site": "MAT", "serial": "SN100",
         "key_identifier": "0BCA25A7-DDF3-4E97-87F1-A643EB656942",
         "key_material": "335357-052701-573265-124388-247709-400708-532015-331848"},
        {"hostname": "FIL-LTP-101", "site": "Filandia", "serial": "SN101",
         "key_identifier": "F70F2436-E285-40B3-AB51-B50CBF6EC24C",
         "key_material": "123456-654321-111111-222222-333333-444444-555555-666666"},
    ]
    assert app_client.post("/import/commit", headers=auth(cris), json=payload).status_code == 403
    r = app_client.post("/import/commit", headers=auth(admin), json=payload)
    assert r.status_code == 200 and r.json()["created"] == 2 and r.json()["skipped"] == 0
    r2 = app_client.post("/import/commit", headers=auth(admin), json=payload)
    assert r2.json()["created"] == 0 and r2.json()["skipped"] == 2


# ---- SR3 + SR4: checkout lifecycle gate ----

def test_duplicate_serial_archive_and_replace(app_client):
    admin = token_for(app_client, "admin", "pw-admin")
    KID = "0BCA25A7-DDF3-4E97-87F1-A643EB656942"
    r = app_client.post("/devices", headers=auth(admin),
                        json={"hostname": "OLD-HOST", "site": "Filandia",
                              "serial": "SN-DUP", "volume_id": KID})
    assert r.status_code == 201

    # same serial without replace -> 409 with conflict details
    r = app_client.post("/devices", headers=auth(admin),
                        json={"hostname": "NEW-HOST", "site": "Matina", "serial": "SN-DUP"})
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["error"] == "duplicate_serial"
    assert detail["existing"][0]["hostname"] == "OLD-HOST"

    # retry with replace_existing -> old archived, new created; only new is active
    r = app_client.post("/devices", headers=auth(admin),
                        json={"hostname": "NEW-HOST", "site": "Matina",
                              "serial": "SN-DUP", "replace_existing": True})
    assert r.status_code == 201
    hits = app_client.get("/devices?q=SN-DUP", headers=auth(admin)).json()
    assert len(hits) == 1 and hits[0]["hostname"] == "NEW-HOST"


def test_recovery_key_format_validation(app_client):
    admin = token_for(app_client, "admin", "pw-admin")
    # bad Recovery Key ID (not a GUID) rejected on create
    assert app_client.post("/devices", headers=auth(admin),
                           json={"hostname": "H1", "site": "Filandia",
                                 "volume_id": "NOT-A-GUID"}).status_code == 422
    # valid create, then enroll a key with loose-but-valid inputs -> normalised on the way out
    r = app_client.post("/devices", headers=auth(admin),
                        json={"hostname": "H2", "site": "Filandia"})
    dev_id = r.json()["id"]
    r = app_client.post(f"/devices/{dev_id}/keys", headers=auth(admin),
                        json={"key_material": "335357 052701 573265 124388 247709 400708 532015 331848",
                              "key_identifier": "0bca25a7 ddf3 4e97 87f1 a643eb656942"})
    assert r.status_code == 201
    assert r.json()["recovery_key_id"] == "0BCA25A7-DDF3-4E97-87F1-A643EB656942"
    # bad key material (not 48 digits) rejected on enroll
    assert app_client.post(f"/devices/{dev_id}/keys", headers=auth(admin),
                           json={"key_material": "123-456"}).status_code == 422


def test_user_management_roles(app_client):
    boss = token_for(app_client, "boss", "pw-boss")     # super_admin
    admin = token_for(app_client, "admin", "pw-admin")  # admin
    aud = token_for(app_client, "auditor", "pw-aud")    # auditor

    # admins and supers can list users; auditors/operators cannot
    assert app_client.get("/operators", headers=auth(admin)).status_code == 200
    assert app_client.get("/operators", headers=auth(boss)).status_code == 200
    assert app_client.get("/operators", headers=auth(aud)).status_code == 403

    # super creates an auditor
    r = app_client.post("/operators", headers=auth(boss),
                        json={"username": "newaud", "password": "pw", "role": "auditor"})
    assert r.status_code == 201
    assert r.json()["mfa_secret"] and r.json()["mfa_uri"].startswith("otpauth://")

    # admin CAN create operators and auditors...
    assert app_client.post("/operators", headers=auth(admin),
                           json={"username": "op-by-admin", "password": "pw",
                                 "role": "operator", "scope": "Filandia"}).status_code == 201
    assert app_client.post("/operators", headers=auth(admin),
                           json={"username": "aud-by-admin", "password": "pw",
                                 "role": "auditor"}).status_code == 201
    # ...but NOT other admins or supers
    assert app_client.post("/operators", headers=auth(admin),
                           json={"username": "admin2", "password": "pw",
                                 "role": "admin"}).status_code == 403
    assert app_client.post("/operators", headers=auth(admin),
                           json={"username": "super2", "password": "pw",
                                 "role": "super_admin"}).status_code == 403

    # super can create an admin, but super_admin is CLI-only even for super
    assert app_client.post("/operators", headers=auth(boss),
                           json={"username": "admin-by-boss", "password": "pw",
                                 "role": "admin"}).status_code == 201
    assert app_client.post("/operators", headers=auth(boss),
                           json={"username": "super-by-boss", "password": "pw",
                                 "role": "super_admin"}).status_code == 403

    # duplicate username rejected; operator role requires a scope
    assert app_client.post("/operators", headers=auth(boss),
                          json={"username": "newaud", "password": "pw", "role": "auditor"}).status_code == 409
    assert app_client.post("/operators", headers=auth(boss),
                          json={"username": "noScope", "password": "pw", "role": "operator"}).status_code == 400


def test_last_super_admin_guardrail(app_client):
    boss = token_for(app_client, "boss", "pw-boss")   # the only super admin in the seed
    ops = app_client.get("/operators", headers=auth(boss)).json()
    boss_id = next(o["id"] for o in ops if o["username"] == "boss")
    # cannot deactivate, delete, or demote the last active super admin
    assert app_client.post(f"/operators/{boss_id}/deactivate", headers=auth(boss)).status_code == 409
    assert app_client.delete(f"/operators/{boss_id}", headers=auth(boss)).status_code == 409
    assert app_client.patch(f"/operators/{boss_id}", headers=auth(boss),
                            json={"role": "admin"}).status_code == 409
    # add a second super admin directly (the API won't create supers) — now the guard relaxes
    from app.db import session_factory
    from app.models import Operator
    from app.security import hash_password
    s = session_factory(app_client.engine)()
    s.add(Operator(username="boss2", password_hash=hash_password("pw"),
                   role="super_admin", status="active", mfa_secret=MFA_SECRET))
    s.commit(); s.close()
    assert app_client.post(f"/operators/{boss_id}/deactivate", headers=auth(boss)).status_code == 200


def test_close_blocked_until_wiped_and_rotated(app_client):
    admin = token_for(app_client, "admin", "pw-admin")
    cris = token_for(app_client, "cris", "pw-cris")
    dev = _seed_device(app_client, admin, cris)

    r = app_client.post("/checkouts", headers=auth(cris),
                        json={"device_id": dev, "ticket_ref": "OS-1234"})
    assert r.status_code == 200, r.text
    cid = r.json()["checkout_id"]
    ptoken = r.json()["provisioning_token"]

    # agent provisions → gets the key to write to USB
    r = app_client.post(f"/checkouts/{cid}/provision",
                        json={"provisioning_token": ptoken, "usb_serial": "USB-77"})
    assert r.status_code == 200 and r.json()["key_material"] == RECOVERY_KEY

    # single-use: second provision is rejected (SR3)
    assert app_client.post(f"/checkouts/{cid}/provision",
                          json={"provisioning_token": ptoken, "usb_serial": "USB-77"}).status_code == 409

    # close is blocked with no wipe / no rotation (SR3+SR4)
    assert app_client.post(f"/checkouts/{cid}/close", headers=auth(cris)).status_code == 409

    # rotate + wipe, then close succeeds
    assert app_client.post(f"/checkouts/{cid}/rotate",
                          json={"new_key_material": NEW_KEY}).status_code == 200
    assert app_client.post(f"/checkouts/{cid}/wipe").status_code == 200
    r = app_client.post(f"/checkouts/{cid}/close", headers=auth(cris))
    assert r.status_code == 200 and r.json()["status"] == "closed"


# ---- SR9: break-glass reveal ----

def test_reveal_forbidden_for_operator(app_client):
    admin = token_for(app_client, "admin", "pw-admin")
    cris = token_for(app_client, "cris", "pw-cris")
    dev = _seed_device(app_client, admin, cris)
    code = pyotp.TOTP(MFA_SECRET).now()
    r = app_client.post(f"/devices/{dev}/reveal", headers=auth(cris),
                        json={"code": code, "reason": "curious"})
    assert r.status_code == 403


def test_reveal_by_super_admin_with_stepup(app_client):
    admin = token_for(app_client, "admin", "pw-admin")
    cris = token_for(app_client, "cris", "pw-cris")
    boss = token_for(app_client, "boss", "pw-boss")
    dev = _seed_device(app_client, admin, cris)
    # wrong step-up code fails
    assert app_client.post(f"/devices/{dev}/reveal", headers=auth(boss),
                          json={"code": "000000", "reason": "USB failed"}).status_code == 401
    # correct step-up succeeds
    code = pyotp.TOTP(MFA_SECRET).now()
    r = app_client.post(f"/devices/{dev}/reveal", headers=auth(boss),
                        json={"code": code, "reason": "USB failed on DSE-FIL-042"})
    assert r.status_code == 200 and r.json()["key_material"] == RECOVERY_KEY


# ---- SR8: audit read + integrity ----

def test_audit_visible_to_auditor_and_valid(app_client):
    admin = token_for(app_client, "admin", "pw-admin")
    cris = token_for(app_client, "cris", "pw-cris")
    aud = token_for(app_client, "auditor", "pw-aud")
    _seed_device(app_client, admin, cris)
    r = app_client.get("/audit", headers=auth(aud))
    assert r.status_code == 200 and r.json()["chain_valid"] is True
    assert any(e["action"] == "device_enrolled" for e in r.json()["entries"])
    # operator may not read the audit log
    assert app_client.get("/audit", headers=auth(cris)).status_code == 403
