import os
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base

# Fallback to local sqlite if not set
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vulnscope.db")
RUNTIME_PROFILE = os.getenv("THREATSCOPE_PROFILE", os.getenv("THREATSCOPE_ENV", "development")).strip().casefold()

# create_engine needs connect_args={"check_same_thread": False} for SQLite
connect_args = {"check_same_thread": False, "timeout": 5} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)


if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _configure_sqlite(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
            # WAL is a production safeguard on the Linux persistent volume. Avoid
            # forcing it on Windows bind-mounted development trees, where Docker
            # Desktop filesystems do not reliably implement SQLite WAL locking.
            if RUNTIME_PROFILE == "production":
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
        finally:
            cursor.close()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
