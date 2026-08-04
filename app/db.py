"""Engine/session helpers. SQLite for dev/test; swap the URL for PostgreSQL in prod."""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .models import Base


def make_engine(url: str = "sqlite:///bitlocker_manager.db"):
    return create_engine(url, future=True)


def make_memory_engine():
    """In-memory SQLite that survives across sessions in one process (for tests)."""
    engine = create_engine(
        "sqlite://", future=True,
        connect_args={"check_same_thread": False}, poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine


def init_db(engine) -> None:
    Base.metadata.create_all(engine)
    run_light_migrations(engine)


def run_light_migrations(engine) -> None:
    """Dev-grade migration: add newly-introduced columns to an existing SQLite DB
    so upgrading doesn't require wiping data. Only ever ADDs columns, never drops.
    Fresh databases (incl. PostgreSQL) get the full schema from create_all instead.
    """
    if engine.dialect.name != "sqlite":
        return
    from sqlalchemy import inspect, text
    insp = inspect(engine)
    if "devices" not in insp.get_table_names():
        return
    cols = {c["name"] for c in insp.get_columns("devices")}
    add = []
    if "archived" not in cols:
        add.append("ALTER TABLE devices ADD COLUMN archived BOOLEAN NOT NULL DEFAULT 0")
    if "archived_at" not in cols:
        add.append("ALTER TABLE devices ADD COLUMN archived_at DATETIME")
    if "archived_by" not in cols:
        add.append("ALTER TABLE devices ADD COLUMN archived_by VARCHAR(36)")
    if add:
        with engine.begin() as conn:
            for stmt in add:
                conn.execute(text(stmt))


def session_factory(engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, future=True)
