"""Bootstrap / admin CLI — create operators and set up their MFA.

Run once to create your first super_admin, then to add operators. Prints a TOTP
enrolment URI you paste into Google Authenticator / Authy (or render as a QR).

Usage:
    python -m tools.seed --db "sqlite:///bitlocker_manager.db" \
        add-operator --username boss --role super_admin --password 's3cret'

    python -m tools.seed list-operators
"""
from __future__ import annotations

import argparse
import sys

import pyotp
from sqlalchemy import select

from app.config import settings
from app.db import make_engine, session_factory
from app.models import Base, Operator
from app.security import hash_password

ROLES = {"operator", "admin", "auditor", "super_admin"}


def _session(db_url: str):
    engine = make_engine(db_url)
    Base.metadata.create_all(engine)
    return session_factory(engine)()


def add_operator(args):
    if args.role not in ROLES:
        sys.exit(f"role must be one of {sorted(ROLES)}")
    if args.role == "operator" and not args.scope:
        sys.exit("operators must have a --scope (site)")
    s = _session(args.db)
    if s.execute(select(Operator).where(Operator.username == args.username)).scalar_one_or_none():
        sys.exit(f"operator '{args.username}' already exists")
    secret = pyotp.random_base32()
    op = Operator(username=args.username, password_hash=hash_password(args.password),
                  role=args.role, scope=args.scope, mfa_secret=secret, status="active")
    s.add(op)
    s.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=args.username, issuer_name="BitLocker Manager")
    print(f"Created operator '{args.username}' (role={args.role}, scope={args.scope or 'ALL'})")
    print("\nMFA enrolment — add this to your authenticator app:")
    print(f"  secret : {secret}")
    print(f"  uri    : {uri}\n")
    print("Tip: paste the URI into any 'otpauth QR generator' to scan it.")


def list_operators(args):
    s = _session(args.db)
    for op in s.execute(select(Operator).order_by(Operator.username)).scalars().all():
        print(f"{op.username:20} role={op.role:12} scope={op.scope or 'ALL':10} status={op.status}")


def remove_operator(args):
    s = _session(args.db)
    op = s.execute(select(Operator).where(Operator.username == args.username)).scalar_one_or_none()
    if op is None:
        sys.exit(f"operator '{args.username}' not found")
    s.delete(op)
    s.commit()
    print(f"Removed operator '{args.username}'.")


def set_password(args):
    s = _session(args.db)
    op = s.execute(select(Operator).where(Operator.username == args.username)).scalar_one_or_none()
    if op is None:
        sys.exit(f"operator '{args.username}' not found")
    op.password_hash = hash_password(args.password)
    s.commit()
    print(f"Password updated for '{args.username}'. (MFA code is unchanged.)")


def main():
    p = argparse.ArgumentParser(description="BitLocker Manager admin tools")
    p.add_argument("--db", default=settings.db_url, help="SQLAlchemy DB URL")
    sub = p.add_subparsers(required=True)

    a = sub.add_parser("add-operator")
    a.add_argument("--username", required=True)
    a.add_argument("--password", required=True)
    a.add_argument("--role", required=True, help=f"one of {sorted(ROLES)}")
    a.add_argument("--scope", default=None, help="site scope (required for operator role)")
    a.set_defaults(func=add_operator)

    lst = sub.add_parser("list-operators")
    lst.set_defaults(func=list_operators)

    rm = sub.add_parser("remove-operator")
    rm.add_argument("--username", required=True)
    rm.set_defaults(func=remove_operator)

    sp = sub.add_parser("set-password")
    sp.add_argument("--username", required=True)
    sp.add_argument("--password", required=True)
    sp.set_defaults(func=set_password)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
