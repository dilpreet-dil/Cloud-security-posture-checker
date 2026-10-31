from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool

from . import config

_kw: dict = {}
if config.DATABASE_URL.startswith("sqlite"):
    _kw["connect_args"] = {"check_same_thread": False}
    if config.DATABASE_URL in ("sqlite://", "sqlite:///:memory:"):
        _kw["poolclass"] = StaticPool

engine = create_engine(config.DATABASE_URL, pool_pre_ping=True, **_kw)
SessionLocal = sessionmaker(bind=engine, autoflush=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
