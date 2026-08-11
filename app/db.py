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

    # operator profile columns (added later than the original schema)
    if "operators" in insp.get_table_names():
        ocols = {c["name"] for c in insp.get_columns("operators")}
        for col, ddl in (
            ("first_name",     "ALTER TABLE operators ADD COLUMN first_name VARCHAR(64)"),
            ("last_name",      "ALTER TABLE operators ADD COLUMN last_name VARCHAR(64)"),
            ("middle_initial", "ALTER TABLE operators ADD COLUMN middle_initial VARCHAR(4)"),
            ("job_title",      "ALTER TABLE operators ADD COLUMN job_title VARCHAR(128)"),
        ):
            if col not in ocols:
                add.append(ddl)

    if add:
        with engine.begin() as conn:
            for stmt in add:
                conn.execute(text(stmt))

    seed_default_sites(engine)


def seed_default_sites(engine) -> None:
    """Ensure the sites pick-list is never empty. Idempotent.

    Seeds the two OAMPI sites the first time, then also backfills any site name
    already referenced by existing devices/operators so the dropdowns show
    everything that's currently in use (important after an upgrade over live data).
    """
    from sqlalchemy import inspect, text
    insp = inspect(engine)
    names = set(insp.get_table_names())
    if "sites" not in names:
        return

    with engine.begin() as conn:
        existing = {r[0] for r in conn.execute(text("SELECT name FROM sites"))}

        wanted: dict[str, str | None] = {"Filandia": "FIL", "Matina": "MAT"}
        # pull site names already in use so nothing silently drops off the list
        for tbl, col in (("devices", "site"), ("operators", "scope")):
            if tbl in names:
                for (val,) in conn.execute(text(f"SELECT DISTINCT {col} FROM {tbl}")):
                    if val and str(val).strip():
                        wanted.setdefault(str(val).strip(), None)

        for name, code in wanted.items():
            if name not in existing:
                conn.execute(
                    text("INSERT INTO sites (id, name, code, is_active, created_at) "
                         "VALUES (:id, :name, :code, 1, :ts)"),
                    {"id": str(_new_uuid()), "name": name, "code": code, "ts": _utcnow()},
                )


def _new_uuid() -> str:
    import uuid
    return str(uuid.uuid4())


def _utcnow():
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc)


def session_factory(engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, future=True)
