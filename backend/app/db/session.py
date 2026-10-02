from __future__ import annotations

from collections.abc import Generator

from contextlib import contextmanager
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

settings = get_settings()

_database_url = settings.sqlalchemy_database_uri
_connect_args = (
    {
        "connect_timeout": 5,
        "options": f"-c statement_timeout={settings.db_statement_timeout_ms}",
    }
    if _database_url.startswith("postgresql")
    else {}
)

_engine_kwargs: dict[str, object] = {
    "pool_pre_ping": True,
    "connect_args": _connect_args,
}

if not _database_url.startswith("sqlite"):
    _engine_kwargs.update(
        {
            "pool_size": settings.db_pool_size,
            "max_overflow": settings.db_max_overflow,
            "pool_timeout": settings.db_pool_timeout,
            "pool_recycle": settings.db_pool_recycle,
        }
    )

engine = create_engine(_database_url, **_engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@contextmanager
def set_query_timeout(session: Session, timeout_ms: int):
    """Temporarily adjust statement_timeout for the current PostgreSQL transaction.

    Used for analytical or aggregate queries that require slightly higher limits
    without relaxing the strict global OLTP statement timeout.
    """
    bind = session.get_bind()
    is_postgres = bind is not None and getattr(bind.dialect, "name", "") == "postgresql"
    if is_postgres:
        session.execute(text(f"SET LOCAL statement_timeout = {int(timeout_ms)}"))
    try:
        yield
    finally:
        pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        try:
            db.rollback()
        except Exception:
            pass
        db.close()
