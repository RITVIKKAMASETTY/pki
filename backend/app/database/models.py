"""
SQLAlchemy ORM models and async database engine.
"""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import (
    Boolean, DateTime, Integer, String, Text, ForeignKey, Float
)
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

DATABASE_URL = "sqlite+aiosqlite:///./pki_analyzer.db"

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    pass


class Certificate(Base):
    __tablename__ = "certificates"

    id: Mapped[int]                   = mapped_column(Integer, primary_key=True, index=True)
    filename: Mapped[str]             = mapped_column(String(256), default="")
    subject: Mapped[str]              = mapped_column(Text)
    subject_cn: Mapped[str]           = mapped_column(String(256), index=True)
    issuer: Mapped[str]               = mapped_column(Text)
    issuer_cn: Mapped[str]            = mapped_column(String(256), index=True)
    serial_number: Mapped[str]        = mapped_column(String(128))
    version: Mapped[int]              = mapped_column(Integer)
    valid_from: Mapped[datetime]      = mapped_column(DateTime)
    valid_until: Mapped[datetime]     = mapped_column(DateTime)
    days_remaining: Mapped[int]       = mapped_column(Integer)
    is_expired: Mapped[bool]          = mapped_column(Boolean, default=False)
    public_key_algorithm: Mapped[str] = mapped_column(String(32))
    public_key_size: Mapped[int]      = mapped_column(Integer)
    signature_algorithm: Mapped[str]  = mapped_column(String(64))
    is_ca: Mapped[bool]               = mapped_column(Boolean, default=False)
    path_length: Mapped[int | None]   = mapped_column(Integer, nullable=True)
    key_usage: Mapped[str]            = mapped_column(Text, default="")
    extended_key_usage: Mapped[str]   = mapped_column(Text, default="")
    subject_alternative_names: Mapped[str] = mapped_column(Text, default="")
    authority_key_identifier: Mapped[str | None] = mapped_column(Text, nullable=True)
    subject_key_identifier: Mapped[str | None]   = mapped_column(Text, nullable=True)
    fingerprint_sha256: Mapped[str]   = mapped_column(String(128), unique=True, index=True)
    fingerprint_sha1: Mapped[str]     = mapped_column(String(64))
    certificate_type: Mapped[str]     = mapped_column(String(16), default="leaf")  # root|intermediate|leaf
    pem_data: Mapped[str]             = mapped_column(Text)

    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="certificate", cascade="all, delete-orphan")
    ai_service: Mapped["AIServiceRecord | None"] = relationship("AIServiceRecord", back_populates="certificate", uselist=False)


class TrustChain(Base):
    __tablename__ = "trust_chains"

    id: Mapped[int]                    = mapped_column(Integer, primary_key=True, index=True)
    leaf_certificate_id: Mapped[int]   = mapped_column(Integer, ForeignKey("certificates.id"))
    root_certificate_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("certificates.id"), nullable=True)
    chain_json: Mapped[str]            = mapped_column(Text)   # JSON list of cert IDs
    status: Mapped[str]                = mapped_column(String(32))  # valid|broken|incomplete|untrusted_root
    issues_json: Mapped[str]           = mapped_column(Text, default="[]")
    validated_at: Mapped[datetime]     = mapped_column(DateTime, default=datetime.utcnow)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int]                = mapped_column(Integer, primary_key=True)
    certificate_id: Mapped[int]    = mapped_column(Integer, ForeignKey("certificates.id"))
    severity: Mapped[str]          = mapped_column(String(16))   # CRITICAL|HIGH|MEDIUM|LOW|INFO
    finding_type: Mapped[str]      = mapped_column(String(64))
    description: Mapped[str]       = mapped_column(Text)
    recommendation: Mapped[str]    = mapped_column(Text)

    certificate: Mapped["Certificate"] = relationship("Certificate", back_populates="findings")


class AIServiceRecord(Base):
    __tablename__ = "ai_services"

    id: Mapped[int]                    = mapped_column(Integer, primary_key=True)
    service_name: Mapped[str]          = mapped_column(String(128))
    domain: Mapped[str]                = mapped_column(String(256))
    certificate_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("certificates.id"), nullable=True)
    status: Mapped[str]                = mapped_column(String(32), default="unknown")

    certificate: Mapped["Certificate | None"] = relationship("Certificate", back_populates="ai_service")


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
