"""Runtime configuration (spec §8). Values come from env; dev defaults are marked
insecure and must be overridden in production.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    jwt_secret: str = os.environ.get("BLM_JWT_SECRET", "dev-insecure-jwt-secret-change-me")
    kek_passphrase: bytes = os.environ.get("BLM_KEK_PASSPHRASE", "dev-insecure-passphrase").encode()
    kek_salt: bytes = os.environ.get("BLM_KEK_SALT", "dev-insecure-salt-16b").encode()
    db_url: str = os.environ.get("BLM_DB_URL", "sqlite:///bitlocker_manager.db")
    access_ttl_seconds: int = int(os.environ.get("BLM_ACCESS_TTL", "3600"))
    mfa_ttl_seconds: int = int(os.environ.get("BLM_MFA_TTL", "300"))
    # Comma-separated origins allowed to call/embed the API (DSE Site, inventory system).
    cors_origins: str = os.environ.get("BLM_CORS_ORIGINS", "*")


settings = Settings()
