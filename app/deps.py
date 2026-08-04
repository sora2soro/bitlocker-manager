"""FastAPI dependencies: DB session, current operator (token auth), RBAC, KEK access."""
from __future__ import annotations

from typing import Iterable

import jwt
from fastapi import Depends, Header, HTTPException, Request, status

from .models import Operator
from .security import decode_token


def get_session(request: Request):
    factory = request.app.state.session_factory
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_kek(request: Request):
    return request.app.state.kek


def get_settings(request: Request):
    return request.app.state.settings


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    return authorization.split(" ", 1)[1].strip()


def get_current_operator(request: Request, authorization: str | None = Header(default=None),
                         session=Depends(get_session)) -> Operator:
    settings = request.app.state.settings
    token = _bearer(authorization)
    try:
        claims = decode_token(settings.jwt_secret, token)
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token")
    if claims.get("kind") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not an access token")
    op = session.get(Operator, claims.get("sub"))
    if op is None or op.status != "active":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown or inactive operator")
    return op


def require_role(*roles: str):
    def _dep(operator: Operator = Depends(get_current_operator)) -> Operator:
        if operator.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"requires role in {roles}")
        return operator
    return _dep


def visible_sites(operator: Operator) -> Iterable[str] | None:
    """None = all sites; otherwise the operator is scoped to their own site (SR5)."""
    if operator.role == "operator" and operator.scope:
        return {operator.scope}
    return None
