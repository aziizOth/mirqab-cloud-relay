"""
Hybrid WAF Tester - Intelligent, Context-Aware WAF Testing Service.

Features:
- Dynamic target fingerprinting (OS, tech stack, WAF detection)
- Context-aware payload selection
- Harmless-but-real attack payloads
- Pattern matching + LLM fallback analysis
"""

import os
import ssl
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from contextlib import asynccontextmanager
from uuid import UUID

import structlog
import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

# Configure logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)

logger = structlog.get_logger(__name__)

# Import components
from .models import (
    init_database, get_session_factory,
    WafTestJob, WafTestResult, Payload,
    PayloadCategory, JobStatus, TestStatus
)
from .discovery import Fingerprinter, Crawler, TargetContext
from .payloads import PayloadDatabase, seed_payloads
from .engine import PayloadSelector, RequestExecutor
from .analyzer import ResponseAnalyzer


# ============================================
# Pydantic Schemas
# ============================================

class TargetConfig(BaseModel):
    """Target configuration."""
    type: str = Field(..., description="Target type: 'url' or 'agent'")
    url: Optional[str] = Field(None, description="Target URL for URL mode")
    agent_id: Optional[str] = Field(None, description="Agent ID for agent mode")
    agent_context: Optional[Dict[str, Any]] = Field(None, description="Pre-collected agent context")
    paths: Optional[List[str]] = Field(None, description="Specific paths to test")


class TestOptions(BaseModel):
    """Test options."""
    categories: Optional[List[str]] = Field(None, description="Attack categories (empty=all)")
    max_payloads_per_endpoint: int = Field(50, description="Max payloads per endpoint")
    rate_limit_rps: int = Field(10, description="Requests per second")
    include_bypass_variants: bool = Field(True, description="Include WAF bypass variants")
    discovery_depth: int = Field(3, description="Crawl depth for URL mode")
    use_llm_analysis: bool = Field(True, description="Enable LLM fallback for ambiguous cases")
    custom_headers: Optional[Dict[str, str]] = Field(None, description="Custom HTTP headers")


class StartTestRequest(BaseModel):
    """Request to start a WAF test."""
    attack_id: Optional[str] = Field(None, description="Attack ID from OffenSight")
    target: TargetConfig
    options: Optional[TestOptions] = None


class TestSummary(BaseModel):
    """Test summary."""
    total_tests: int
    blocked: int
    vulnerable: int
    not_vulnerable: int
    errors: int
    effectiveness_pct: float


class TestResponse(BaseModel):
    """WAF test response."""
    job_id: str
    status: str
    progress: int = 0
    target_info: Optional[Dict[str, Any]] = None
    summary: Optional[TestSummary] = None
    findings: Optional[List[Dict[str, Any]]] = None


class QuickTestRequest(BaseModel):
    """Quick single payload test."""
    target_url: str
    payload: str
    param_name: str = "q"
    category: str = "xss"


# ============================================
# Application State
# ============================================

class AppState:
    """Application state."""
    session_factory: Any = None
    fingerprinter: Fingerprinter = None
    crawler: Crawler = None
    analyzer: ResponseAnalyzer = None
    jobs: Dict[str, WafTestJob] = {}


app_state = AppState()


def get_db() -> Session:
    """Get database session."""
    session = app_state.session_factory()
    try:
        yield session
    finally:
        session.close()


# ============================================
# Lifespan
# ============================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan."""
    logger.info("waf_tester_starting")

    # Initialize database
    init_database()
    app_state.session_factory = get_session_factory()

    # Seed payloads
    session = app_state.session_factory()
    try:
        count = seed_payloads(session)
        logger.info("payloads_seeded", count=count)
    finally:
        session.close()

    # Initialize components
    app_state.fingerprinter = Fingerprinter()
    app_state.crawler = Crawler()
    app_state.analyzer = ResponseAnalyzer(
        use_llm=os.getenv("ENABLE_LLM_ANALYSIS", "true").lower() == "true",
        llm_api_key=os.getenv("OPENAI_API_KEY"),
    )

    yield

    logger.info("waf_tester_stopped")


# ============================================
# FastAPI App
# ============================================

app = FastAPI(
    title="Hybrid WAF Tester",
    description="Intelligent, context-aware WAF testing service",
    version="2.0.0",
    lifespan=lifespan,
)


# ============================================
# Test Orchestration
# ============================================

async def run_waf_test(job_id: str, request: StartTestRequest, db: Session):
    """Run a complete WAF test job."""
    job = db.query(WafTestJob).filter(WafTestJob.id == job_id).first()
    if not job:
        logger.error("job_not_found", job_id=job_id)
        return

    try:
        job.status = JobStatus.DISCOVERING
        job.started_at = datetime.now(timezone.utc)
        db.commit()

        target = request.target
        options = request.options or TestOptions()

        # ============================================
        # Phase 1: Discovery
        # ============================================
        logger.info("discovery_started", job_id=str(job_id), target_type=target.type)

        if target.type == "agent" and target.agent_context:
            # Agent-assisted mode - use provided context
            context = app_state.fingerprinter.analyze_agent_context(target.agent_context)
        else:
            # URL mode - fingerprint and crawl
            executor = RequestExecutor(rate_limit=options.rate_limit_rps)
            baseline = await executor.execute_baseline(target.url, options.custom_headers)

            # Fingerprint
            context = app_state.fingerprinter.analyze_response(
                url=target.url,
                status_code=baseline.get("status_code", 200),
                headers=baseline.get("response_headers", {}),
                body=baseline.get("response_body", ""),
            )

            # Crawl for endpoints
            if options.discovery_depth > 0:
                endpoints, params = await app_state.crawler.crawl(
                    target.url,
                    custom_headers=options.custom_headers,
                )
                context.endpoints = [e.to_dict() for e in endpoints]
                context.parameters = [p.to_dict() for p in params]

        # Update job with discovery results
        job.discovered_os = context.os
        job.discovered_tech = context.tech
        job.discovered_server = context.server
        job.discovered_framework = context.framework
        job.discovered_db = context.db
        job.discovered_waf = context.waf
        job.discovered_endpoints = context.endpoints
        job.discovered_parameters = context.parameters
        db.commit()

        logger.info(
            "discovery_complete",
            job_id=str(job_id),
            os=context.os,
            tech=context.tech,
            waf=context.waf,
            endpoints=len(context.endpoints),
        )

        # ============================================
        # Phase 2: Payload Selection
        # ============================================
        job.status = JobStatus.RUNNING
        db.commit()

        payload_db = PayloadDatabase(db)
        selector = PayloadSelector(payload_db)

        # Determine categories to test
        categories = None
        if options.categories:
            categories = [PayloadCategory(c) for c in options.categories if c in PayloadCategory.__members__.values()]

        # Select payloads for all categories
        all_selections = selector.select_all_categories(
            context=context,
            categories=categories,
            max_per_category=options.max_payloads_per_endpoint,
            include_bypass=options.include_bypass_variants,
        )

        total_payloads = sum(len(sels) for sels in all_selections.values())
        logger.info(
            "payloads_selected",
            job_id=str(job_id),
            total=total_payloads,
            categories=list(all_selections.keys()),
        )

        # ============================================
        # Phase 3: Execution
        # ============================================
        executor = RequestExecutor(
            rate_limit=options.rate_limit_rps,
            timeout=10,
        )

        all_results = []
        payload_map = {}
        completed = 0
        total = sum(
            len(sel.injection_points) * len(selections)
            for selections in all_selections.values()
            for sel in selections
        )

        for category, selections in all_selections.items():
            for selection in selections:
                payload_map[selection.payload.id] = selection.payload

            # Execute
            results = await executor.execute_selections(
                base_url=target.url,
                selections=selections,
                custom_headers=options.custom_headers,
                progress_callback=lambda c, t: None,  # Could update job.progress here
            )

            all_results.extend(results)
            completed += len(results)

            # Update progress
            job.progress = int((completed / total) * 100) if total > 0 else 0
            db.commit()

        # ============================================
        # Phase 4: Analysis
        # ============================================
        baseline = await executor.execute_baseline(target.url, options.custom_headers)

        analyzed_results = await app_state.analyzer.analyze_batch(
            results=all_results,
            payloads=payload_map,
            baseline=baseline,
        )

        # ============================================
        # Phase 5: Store Results
        # ============================================
        blocked = 0
        vulnerable = 0
        not_vulnerable = 0
        errors = 0

        for result in analyzed_results:
            test_result = WafTestResult(
                job_id=job.id,
                endpoint=result.endpoint,
                parameter=result.parameter,
                param_location=result.param_location,
                attack_category=payload_map.get(result.payload_id, Payload()).category if result.payload_id in payload_map else PayloadCategory.XSS,
                payload_id=result.payload_id,
                payload=result.payload,
                status=result.test_status,
                confidence=result.confidence,
                analysis_method=result.analysis_method,
                evidence=result.evidence,
                response_status=result.status_code,
                response_time_ms=result.response_time_ms,
                response_length=result.response_length,
                waf_signature=result.waf_signature,
            )
            db.add(test_result)

            if result.test_status == TestStatus.BLOCKED:
                blocked += 1
            elif result.test_status == TestStatus.VULNERABLE:
                vulnerable += 1
            elif result.test_status == TestStatus.NOT_VULNERABLE:
                not_vulnerable += 1
            else:
                errors += 1

        # Update job summary
        job.total_tests = len(analyzed_results)
        job.blocked_count = blocked
        job.vulnerable_count = vulnerable
        job.not_vulnerable_count = not_vulnerable
        job.error_count = errors
        job.status = JobStatus.COMPLETED
        job.completed_at = datetime.now(timezone.utc)
        job.progress = 100
        db.commit()

        logger.info(
            "test_completed",
            job_id=str(job_id),
            total=len(analyzed_results),
            blocked=blocked,
            vulnerable=vulnerable,
            effectiveness_pct=round((blocked / len(analyzed_results) * 100), 1) if analyzed_results else 0,
        )

    except Exception as e:
        logger.exception("test_failed", job_id=str(job_id), error=str(e))
        job.status = JobStatus.FAILED
        job.error_message = str(e)
        db.commit()


# ============================================
# API Endpoints
# ============================================

@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy", "service": "waf-tester", "version": "2.0.0"}


@app.post("/waf/test", response_model=TestResponse)
async def start_test(
    request: StartTestRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Start a new WAF test."""
    # Validate target
    if request.target.type == "url" and not request.target.url:
        raise HTTPException(400, "URL required for URL mode")

    # Create job
    options = request.options or TestOptions()
    job = WafTestJob(
        attack_id=request.attack_id,
        target_type=request.target.type,
        target_url=request.target.url or "",
        target_agent_id=request.target.agent_id,
        attack_categories=[c for c in (options.categories or [])],
        max_payloads_per_endpoint=options.max_payloads_per_endpoint,
        rate_limit_rps=options.rate_limit_rps,
        include_bypass_variants=options.include_bypass_variants,
        discovery_depth=options.discovery_depth,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Start background task
    background_tasks.add_task(run_waf_test, str(job.id), request, db)

    return TestResponse(
        job_id=str(job.id),
        status=job.status.value,
        progress=0,
    )


@app.get("/waf/test/{job_id}", response_model=TestResponse)
async def get_test(job_id: str, db: Session = Depends(get_db)):
    """Get test status and results."""
    try:
        uuid_id = UUID(job_id)
    except ValueError:
        raise HTTPException(400, "Invalid job ID")

    job = db.query(WafTestJob).filter(WafTestJob.id == uuid_id).first()
    if not job:
        raise HTTPException(404, "Job not found")

    # Build response
    response = TestResponse(
        job_id=str(job.id),
        status=job.status.value,
        progress=job.progress,
    )

    # Add target info if discovered
    if job.discovered_tech or job.discovered_os:
        response.target_info = {
            "os": job.discovered_os,
            "tech": job.discovered_tech,
            "server": job.discovered_server,
            "framework": job.discovered_framework,
            "db": job.discovered_db,
            "waf": job.discovered_waf,
            "endpoints_discovered": len(job.discovered_endpoints or []),
        }

    # Add summary if completed
    if job.status == JobStatus.COMPLETED:
        total = job.total_tests or 1
        response.summary = TestSummary(
            total_tests=job.total_tests,
            blocked=job.blocked_count,
            vulnerable=job.vulnerable_count,
            not_vulnerable=job.not_vulnerable_count,
            errors=job.error_count,
            effectiveness_pct=round((job.blocked_count / total * 100), 1),
        )

        # Add top findings (vulnerabilities)
        results = db.query(WafTestResult).filter(
            WafTestResult.job_id == job.id,
            WafTestResult.status == TestStatus.VULNERABLE,
        ).limit(20).all()

        response.findings = [
            {
                "endpoint": r.endpoint,
                "parameter": r.parameter,
                "category": r.attack_category.value,
                "payload": r.payload[:100],
                "confidence": r.confidence,
                "evidence": r.evidence,
                "waf_bypassed": r.waf_signature is None,
            }
            for r in results
        ]

    return response


@app.get("/waf/test/{job_id}/results")
async def get_test_results(
    job_id: str,
    status: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """Get detailed test results."""
    try:
        uuid_id = UUID(job_id)
    except ValueError:
        raise HTTPException(400, "Invalid job ID")

    query = db.query(WafTestResult).filter(WafTestResult.job_id == uuid_id)

    if status:
        query = query.filter(WafTestResult.status == TestStatus(status))

    if category:
        query = query.filter(WafTestResult.attack_category == PayloadCategory(category))

    total = query.count()
    results = query.offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "results": [r.to_dict() if hasattr(r, 'to_dict') else {
            "id": str(r.id),
            "endpoint": r.endpoint,
            "parameter": r.parameter,
            "category": r.attack_category.value,
            "payload": r.payload,
            "status": r.status.value,
            "confidence": r.confidence,
            "evidence": r.evidence,
            "response_status": r.response_status,
            "response_time_ms": r.response_time_ms,
            "waf_signature": r.waf_signature,
        } for r in results],
    }


@app.post("/waf/discover")
async def discover_target(
    target: TargetConfig,
    custom_headers: Optional[Dict[str, str]] = None,
):
    """Run discovery only (no attacks)."""
    if target.type != "url" or not target.url:
        raise HTTPException(400, "URL required for discovery")

    executor = RequestExecutor()
    baseline = await executor.execute_baseline(target.url, custom_headers)

    if baseline.get("error"):
        raise HTTPException(502, f"Failed to reach target: {baseline['error']}")

    context = app_state.fingerprinter.analyze_response(
        url=target.url,
        status_code=baseline.get("status_code", 200),
        headers=baseline.get("response_headers", {}),
        body=baseline.get("response_body", ""),
    )

    # Quick endpoint discovery
    endpoints, params = await app_state.crawler.quick_discover(target.url, custom_headers)

    return {
        "url": target.url,
        "os": context.os,
        "tech": context.tech,
        "server": context.server,
        "framework": context.framework,
        "db": context.db,
        "waf": context.waf,
        "confidence_scores": context.confidence_scores,
        "endpoints": [e.to_dict() for e in endpoints],
        "parameters": [p.to_dict() for p in params],
    }


@app.post("/waf/quicktest")
async def quick_test(request: QuickTestRequest):
    """Quick test with a single payload."""
    executor = RequestExecutor()
    result = await executor.quick_test(
        url=request.target_url,
        payload=request.payload,
        param_name=request.param_name,
    )

    # Quick analysis
    is_blocked, waf_name = app_state.fingerprinter.detect_waf_block(
        status_code=result.status_code or 0,
        headers=result.response_headers,
        body=result.response_body,
    ) if result.status_code else (False, None)

    return {
        "payload": request.payload,
        "target": request.target_url,
        "status_code": result.status_code,
        "response_time_ms": result.response_time_ms,
        "blocked": is_blocked,
        "waf_detected": waf_name,
        "response_preview": result.response_body[:500] if result.response_body else None,
    }


@app.get("/waf/payloads")
async def list_payloads(
    category: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List available payloads."""
    payload_db = PayloadDatabase(db)

    if category:
        try:
            cat = PayloadCategory(category)
            payloads = payload_db.get_all_by_category(cat)
            return {
                "category": category,
                "count": len(payloads),
                "payloads": [
                    {
                        "id": p.id,
                        "payload": p.payload,
                        "description": p.description,
                        "target_os": p.target_os.value,
                        "target_tech": p.target_tech,
                    }
                    for p in payloads
                ],
            }
        except ValueError:
            raise HTTPException(400, f"Invalid category: {category}")

    return payload_db.get_stats()


@app.get("/waf/categories")
async def list_categories():
    """List attack categories with recommendations."""
    return {
        "categories": [
            {"id": c.value, "name": c.name}
            for c in PayloadCategory
        ]
    }


# ============================================
# Main
# ============================================

if __name__ == "__main__":
    ssl_context = None
    cert_file = "/app/certs/tls.crt"
    key_file = "/app/certs/tls.key"

    if os.path.exists(cert_file) and os.path.exists(key_file):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert_file, key_file)

    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=8443,
        ssl_keyfile=key_file if ssl_context else None,
        ssl_certfile=cert_file if ssl_context else None,
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
    )
