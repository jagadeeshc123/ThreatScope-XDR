from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class ProductionRuntimeMetadata(Base):
    __tablename__ = "production_runtime_metadata"

    id = Column(Integer, primary_key=True)
    key = Column(String(80), unique=True, nullable=False, index=True)
    value = Column(String(256), nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
