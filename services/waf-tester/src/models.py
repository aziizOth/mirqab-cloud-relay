"""
Database models for Hybrid WAF Tester.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List
from uuid import uuid4

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, JSON,
    ForeignKey, Enum as SQLEnum, create_engine
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()


def enum_values(enum_class):
    """Get enum values for SQLEnum creation."""
    return [e.value for e in enum_class]


class PayloadCategory(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    CMDI = "cmdi"
    LFI = "lfi"
    RFI = "rfi"
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "ssti"
    PATH_TRAVERSAL = "path_traversal"
    OPEN_REDIRECT = "open_redirect"
    HEADER_INJECTION = "header_injection"


class TargetOS(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    BOTH = "both"


class TargetTech(str, Enum):
    PHP = "php"
    ASP = "asp"
    ASPNET = "asp.net"
    JAVA = "java"
    NODE = "node"
    PYTHON = "python"
    RUBY = "ruby"
    GO = "go"
    GENERIC = "generic"


class TargetDB(str, Enum):
    MYSQL = "mysql"
    MARIADB = "mariadb"
    MSSQL = "mssql"
    POSTGRESQL = "postgresql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    MONGODB = "mongodb"
    GENERIC = "generic"


class TestStatus(str, Enum):
    BLOCKED = "blocked"
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    ERROR = "error"
    TIMEOUT = "timeout"


class JobStatus(str, Enum):
    PENDING = "pending"
    DISCOVERING = "discovering"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Payload(Base):
    """Payload definition with targeting metadata."""
    __tablename__ = "payloads"

    id = Column(String(100), primary_key=True)
    category = Column(
        SQLEnum(PayloadCategory, values_callable=enum_values, create_constraint=True, native_enum=True),
        nullable=False, index=True
    )
    subcategory = Column(String(50), nullable=True)

    payload = Column(Text, nullable=False)
    encoded_variants = Column(JSON, default={})  # {"url": "...", "double_url": "..."}

    # Targeting
    target_tech = Column(JSON, default=["generic"])  # ["mysql", "mariadb"] or ["generic"]
    target_os = Column(
        SQLEnum(TargetOS, values_callable=enum_values, create_constraint=True, native_enum=True),
        default=TargetOS.BOTH
    )
    target_param_location = Column(String(20), default="any")  # query, body, header, cookie, any

    # Detection
    success_pattern = Column(Text, nullable=True)  # Regex to detect success
    success_indicator = Column(String(50), default="content_change")  # content_change, error, time_delay
    expected_delay_ms = Column(Integer, nullable=True)  # For time-based detection

    # Safety
    is_harmless = Column(Boolean, default=True)
    risk_level = Column(String(20), default="safe")  # safe, low, medium (no high)

    # Metadata
    description = Column(Text, nullable=True)
    references = Column(JSON, default=[])  # CVE, OWASP, etc.

    created_at = Column(DateTime, default=datetime.utcnow)


class WafTestJob(Base):
    """WAF test job tracking."""
    __tablename__ = "waf_test_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    attack_id = Column(String(50), nullable=True)  # From OffenSight

    # Target
    target_type = Column(String(20), nullable=False)  # agent, url
    target_url = Column(Text, nullable=False)
    target_agent_id = Column(String(100), nullable=True)

    # Status
    status = Column(
        SQLEnum(JobStatus, values_callable=enum_values, create_constraint=True, native_enum=True),
        default=JobStatus.PENDING
    )
    progress = Column(Integer, default=0)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    # Discovery results
    discovered_os = Column(String(50), nullable=True)
    discovered_tech = Column(String(50), nullable=True)
    discovered_server = Column(String(50), nullable=True)
    discovered_framework = Column(String(50), nullable=True)
    discovered_db = Column(String(50), nullable=True)
    discovered_waf = Column(String(50), nullable=True)
    discovered_endpoints = Column(JSON, default=[])
    discovered_parameters = Column(JSON, default=[])

    # Options
    attack_categories = Column(JSON, default=[])  # Empty = all
    max_payloads_per_endpoint = Column(Integer, default=50)
    rate_limit_rps = Column(Integer, default=10)
    include_bypass_variants = Column(Boolean, default=True)
    discovery_depth = Column(Integer, default=3)

    # Summary
    total_tests = Column(Integer, default=0)
    blocked_count = Column(Integer, default=0)
    vulnerable_count = Column(Integer, default=0)
    not_vulnerable_count = Column(Integer, default=0)
    error_count = Column(Integer, default=0)

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    results = relationship("WafTestResult", back_populates="job", cascade="all, delete-orphan")


class WafTestResult(Base):
    """Individual WAF test result."""
    __tablename__ = "waf_test_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("waf_test_jobs.id"), nullable=False)

    # Target
    endpoint = Column(String(500), nullable=False)
    parameter = Column(String(100), nullable=True)
    param_location = Column(String(20), nullable=True)  # query, body, header, cookie

    # Attack
    attack_category = Column(
        SQLEnum(PayloadCategory, values_callable=enum_values, create_constraint=True, native_enum=True),
        nullable=False
    )
    payload_id = Column(String(100), nullable=True)
    payload = Column(Text, nullable=False)

    # Result
    status = Column(
        SQLEnum(TestStatus, values_callable=enum_values, create_constraint=True, native_enum=True),
        nullable=False
    )
    confidence = Column(Float, default=0.0)
    analysis_method = Column(String(50), nullable=True)  # pattern_match, time_based, llm_analysis
    evidence = Column(Text, nullable=True)

    # Response details
    response_status = Column(Integer, nullable=True)
    response_time_ms = Column(Integer, nullable=True)
    response_length = Column(Integer, nullable=True)
    waf_signature = Column(String(100), nullable=True)  # Detected WAF that blocked

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    job = relationship("WafTestJob", back_populates="results")


class FingerprintRule(Base):
    """Fingerprint rules for technology detection."""
    __tablename__ = "fingerprint_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_type = Column(String(50), nullable=False)  # header, path, extension, error, cookie
    pattern = Column(Text, nullable=False)

    # What this pattern detects
    detected_os = Column(String(50), nullable=True)
    detected_tech = Column(String(50), nullable=True)
    detected_server = Column(String(50), nullable=True)
    detected_framework = Column(String(50), nullable=True)
    detected_db = Column(String(50), nullable=True)
    detected_waf = Column(String(50), nullable=True)

    priority = Column(Integer, default=0)

    created_at = Column(DateTime, default=datetime.utcnow)


# Database setup
def get_database_url():
    import os
    return os.getenv("DATABASE_URL", "postgresql://relay:relay@localhost:5432/relay")


def create_db_engine():
    return create_engine(get_database_url())


def get_session_factory():
    engine = create_db_engine()
    return sessionmaker(bind=engine)


def init_database():
    """Initialize database tables."""
    engine = create_db_engine()
    Base.metadata.create_all(engine)
