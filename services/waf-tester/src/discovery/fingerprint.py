"""
Fingerprint engine for target technology detection.
Uses rules-based detection (no LLM required).
"""

import re
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class TargetContext:
    """Discovered target context."""
    url: str
    os: Optional[str] = None
    server: Optional[str] = None
    tech: Optional[str] = None
    framework: Optional[str] = None
    db: Optional[str] = None
    waf: Optional[str] = None
    endpoints: List[Dict[str, Any]] = field(default_factory=list)
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    confidence_scores: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "os": self.os,
            "server": self.server,
            "tech": self.tech,
            "framework": self.framework,
            "db": self.db,
            "waf": self.waf,
            "endpoints": self.endpoints,
            "parameters": self.parameters,
            "confidence_scores": self.confidence_scores,
        }


# Fingerprint rules - no database needed, pure rules
HEADER_FINGERPRINTS = {
    # Server detection
    "server": {
        r"nginx/?[\d.]*": {"server": "nginx", "os_hint": "linux"},
        r"Apache/?[\d.]*": {"server": "apache"},
        r"Microsoft-IIS/?[\d.]*": {"server": "iis", "os": "windows"},
        r"LiteSpeed": {"server": "litespeed"},
        r"openresty": {"server": "openresty"},
        r"cloudflare": {"server": "cloudflare"},
    },
    # Technology detection
    "x-powered-by": {
        r"PHP/?[\d.]*": {"tech": "php", "os_hint": "linux"},
        r"ASP\.NET": {"tech": "asp.net", "os": "windows"},
        r"Express": {"tech": "node"},
        r"Servlet": {"tech": "java"},
        r"JSF": {"tech": "java", "framework": "jsf"},
        r"Phusion Passenger": {"tech": "ruby"},
    },
    # Framework detection
    "x-generator": {
        r"WordPress[\d. ]*": {"framework": "wordpress", "tech": "php"},
        r"Drupal[\d. ]*": {"framework": "drupal", "tech": "php"},
        r"Joomla": {"framework": "joomla", "tech": "php"},
    },
    # WAF detection
    "x-sucuri-id": {"waf": "sucuri"},
    "x-cdn": {
        r"Incapsula": {"waf": "incapsula"},
    },
    "server-timing": {
        r"cf-": {"waf": "cloudflare"},
    },
}

# Cookie-based detection
COOKIE_FINGERPRINTS = {
    r"__cfduid": {"waf": "cloudflare"},
    r"incap_ses_": {"waf": "incapsula"},
    r"visid_incap_": {"waf": "incapsula"},
    r"PHPSESSID": {"tech": "php"},
    r"JSESSIONID": {"tech": "java"},
    r"ASP\.NET_SessionId": {"tech": "asp.net", "os": "windows"},
    r"ASPSESSIONID": {"tech": "asp", "os": "windows"},
    r"_rails_session": {"tech": "ruby", "framework": "rails"},
    r"laravel_session": {"tech": "php", "framework": "laravel"},
    r"connect\.sid": {"tech": "node"},
}

# Response body fingerprints
BODY_FINGERPRINTS = {
    # Error messages - database detection
    r"mysql_fetch|mysqli_|MySQL.*error": {"db": "mysql"},
    r"ORA-\d{5}": {"db": "oracle"},
    r"Microsoft OLE DB.*SQL Server|ODBC SQL Server": {"db": "mssql"},
    r"pg_query|PostgreSQL.*ERROR": {"db": "postgresql"},
    r"sqlite3?_": {"db": "sqlite"},
    # Error messages - technology detection
    r"Parse error.*\.php": {"tech": "php"},
    r"Fatal error.*\.php": {"tech": "php"},
    r"Warning.*\.php": {"tech": "php"},
    r"<b>Warning</b>:.*php": {"tech": "php"},
    r"ASP\.NET.*Exception": {"tech": "asp.net", "os": "windows"},
    r"System\.Web\.HttpException": {"tech": "asp.net"},
    r"java\.lang\.\w+Exception": {"tech": "java"},
    r"Traceback \(most recent call": {"tech": "python"},
    r"TypeError.*undefined is not": {"tech": "node"},
    # Framework detection
    r"wp-content|wp-includes": {"framework": "wordpress", "tech": "php"},
    r"/administrator/|com_content": {"framework": "joomla", "tech": "php"},
    r"sites/default/files": {"framework": "drupal", "tech": "php"},
    r"laravel.*exception": {"framework": "laravel", "tech": "php"},
    r"django\.": {"framework": "django", "tech": "python"},
    r"Rails\.": {"framework": "rails", "tech": "ruby"},
    r"Spring.*Exception": {"framework": "spring", "tech": "java"},
}

# URL path fingerprints
PATH_FINGERPRINTS = {
    r"/wp-admin": {"framework": "wordpress", "tech": "php"},
    r"/wp-content": {"framework": "wordpress", "tech": "php"},
    r"/wp-includes": {"framework": "wordpress", "tech": "php"},
    r"/administrator": {"framework": "joomla", "tech": "php"},
    r"/typo3": {"framework": "typo3", "tech": "php"},
    r"/sites/default": {"framework": "drupal", "tech": "php"},
    r"/api/swagger": {"api": "swagger"},
    r"/graphql": {"api": "graphql"},
    r"/\.git": {"exposed": "git"},
    r"/\.env": {"exposed": "env"},
}

# Extension fingerprints
EXTENSION_FINGERPRINTS = {
    r"\.php\d?$": {"tech": "php"},
    r"\.asp$": {"tech": "asp", "os": "windows"},
    r"\.aspx$": {"tech": "asp.net", "os": "windows"},
    r"\.jsp$": {"tech": "java"},
    r"\.do$": {"tech": "java", "framework": "struts"},
    r"\.action$": {"tech": "java", "framework": "struts"},
    r"\.py$": {"tech": "python"},
    r"\.rb$": {"tech": "ruby"},
    r"\.cgi$": {"tech": "cgi"},
    r"\.pl$": {"tech": "perl"},
}

# WAF block page signatures
WAF_SIGNATURES = {
    "cloudflare": [
        r"Attention Required.*Cloudflare",
        r"cf-ray",
        r"Ray ID:",
        r"cloudflare\.com/5xx-error-landing",
    ],
    "modsecurity": [
        r"ModSecurity",
        r"OWASP.*CRS",
        r"Request Rejected",
        r"mod_security",
    ],
    "aws_waf": [
        r"Request blocked",
        r"AWS WAF",
        r"x-amzn-RequestId",
    ],
    "akamai": [
        r"AkamaiGHost",
        r"Reference.*#[\d.]+",
    ],
    "sucuri": [
        r"sucuri\.net",
        r"Access Denied.*Sucuri",
    ],
    "f5_bigip": [
        r"BIG-IP",
        r"BigIP",
        r"The requested URL was rejected",
    ],
    "barracuda": [
        r"Barracuda",
        r"barra.*firewall",
    ],
    "imperva": [
        r"Incapsula",
        r"Request unsuccessful",
        r"visid_incap",
    ],
    "fortinet": [
        r"FortiWeb",
        r"fortigate",
    ],
    "generic": [
        r"Access Denied",
        r"Forbidden",
        r"Request Blocked",
        r"Security Violation",
        r"Your request has been blocked",
        r"Web Application Firewall",
    ],
}


class Fingerprinter:
    """Technology fingerprinting engine."""

    def __init__(self):
        self.logger = logger.bind(component="fingerprinter")

    def analyze_response(
        self,
        url: str,
        status_code: int,
        headers: Dict[str, str],
        body: str,
        cookies: Dict[str, str] = None,
    ) -> TargetContext:
        """Analyze HTTP response to fingerprint target."""
        context = TargetContext(url=url)
        detections = {}  # Track all detections with confidence

        # Analyze headers
        self._analyze_headers(headers, detections)

        # Analyze cookies
        if cookies:
            self._analyze_cookies(cookies, detections)

        # Analyze response body
        self._analyze_body(body, detections)

        # Analyze URL path
        self._analyze_path(url, detections)

        # Check for WAF block
        if status_code in (403, 406, 429, 503):
            self._detect_waf(body, headers, detections)

        # Resolve detections to context
        self._resolve_context(context, detections)

        self.logger.info(
            "fingerprint_complete",
            url=url,
            os=context.os,
            tech=context.tech,
            server=context.server,
            framework=context.framework,
            db=context.db,
            waf=context.waf,
        )

        return context

    def _analyze_headers(self, headers: Dict[str, str], detections: Dict):
        """Analyze HTTP headers for technology fingerprints."""
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header_name, patterns in HEADER_FINGERPRINTS.items():
            header_value = headers_lower.get(header_name, "")
            if not header_value:
                continue

            if isinstance(patterns, dict):
                # Pattern-based matching
                for pattern, detected in patterns.items():
                    if re.search(pattern, header_value, re.I):
                        self._add_detection(detections, detected, 0.9, f"header:{header_name}")
            else:
                # Direct detection (e.g., x-sucuri-id presence)
                self._add_detection(detections, patterns, 0.9, f"header:{header_name}")

    def _analyze_cookies(self, cookies: Dict[str, str], detections: Dict):
        """Analyze cookies for technology fingerprints."""
        cookie_names = " ".join(cookies.keys())

        for pattern, detected in COOKIE_FINGERPRINTS.items():
            if re.search(pattern, cookie_names, re.I):
                self._add_detection(detections, detected, 0.7, "cookie")

    def _analyze_body(self, body: str, detections: Dict):
        """Analyze response body for technology fingerprints."""
        for pattern, detected in BODY_FINGERPRINTS.items():
            if re.search(pattern, body, re.I):
                self._add_detection(detections, detected, 0.8, "body")

    def _analyze_path(self, url: str, detections: Dict):
        """Analyze URL path for technology fingerprints."""
        for pattern, detected in PATH_FINGERPRINTS.items():
            if re.search(pattern, url, re.I):
                self._add_detection(detections, detected, 0.85, "path")

        # Extension analysis
        for pattern, detected in EXTENSION_FINGERPRINTS.items():
            if re.search(pattern, url, re.I):
                self._add_detection(detections, detected, 0.9, "extension")

    def _detect_waf(self, body: str, headers: Dict[str, str], detections: Dict):
        """Detect WAF from block response."""
        headers_str = " ".join(f"{k}: {v}" for k, v in headers.items())
        combined = f"{body} {headers_str}"

        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if re.search(sig, combined, re.I):
                    self._add_detection(
                        detections,
                        {"waf": waf_name},
                        0.95,
                        "waf_signature"
                    )
                    return  # Stop after first WAF match

    def _add_detection(
        self,
        detections: Dict,
        detected: Dict,
        confidence: float,
        source: str
    ):
        """Add a detection with confidence tracking."""
        for key, value in detected.items():
            if key not in detections:
                detections[key] = []
            detections[key].append({
                "value": value,
                "confidence": confidence,
                "source": source,
            })

    def _resolve_context(self, context: TargetContext, detections: Dict):
        """Resolve multiple detections to final context."""
        for key in ["os", "tech", "server", "framework", "db", "waf"]:
            if key in detections:
                # Get highest confidence detection
                sorted_detections = sorted(
                    detections[key],
                    key=lambda x: x["confidence"],
                    reverse=True
                )
                if sorted_detections:
                    best = sorted_detections[0]
                    setattr(context, key, best["value"])
                    context.confidence_scores[key] = best["confidence"]

        # Handle os_hint (lower confidence than direct os detection)
        if not context.os and "os_hint" in detections:
            hints = detections["os_hint"]
            if hints:
                context.os = hints[0]["value"]
                context.confidence_scores["os"] = hints[0]["confidence"] * 0.7

    def detect_waf_block(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str
    ) -> Optional[str]:
        """Detect if response is a WAF block and return WAF name."""
        if status_code not in (403, 406, 429, 503):
            return None

        headers_str = " ".join(f"{k}: {v}" for k, v in headers.items())
        combined = f"{body} {headers_str}"

        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if re.search(sig, combined, re.I):
                    return waf_name

        # Generic block detection
        if status_code == 403:
            return "unknown"

        return None

    def analyze_agent_context(self, agent_data: Dict[str, Any]) -> TargetContext:
        """Build context from agent-provided reconnaissance data."""
        context = TargetContext(
            url=agent_data.get("internal_url", ""),
            os=agent_data.get("os_type"),
            server=agent_data.get("web_server"),
            tech=agent_data.get("technology"),
            framework=agent_data.get("framework"),
            db=agent_data.get("database"),
            waf=agent_data.get("waf_detected"),
            endpoints=agent_data.get("endpoints", []),
            parameters=agent_data.get("parameters", []),
        )

        # Set high confidence for agent-provided data
        for key in ["os", "tech", "server", "framework", "db", "waf"]:
            if getattr(context, key):
                context.confidence_scores[key] = 0.95

        return context
