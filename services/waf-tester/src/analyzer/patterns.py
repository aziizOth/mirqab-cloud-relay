"""
Pattern-based response analyzer.
Handles 95%+ of analysis without LLM.
"""

import re
from typing import Optional, Dict, Tuple
from dataclasses import dataclass
import structlog

from ..models import Payload, TestStatus, PayloadCategory
from ..engine.executor import ExecutionResult

logger = structlog.get_logger(__name__)


# WAF block signatures
WAF_SIGNATURES = {
    "cloudflare": [
        r"Attention Required.*Cloudflare",
        r"cf-ray",
        r"Ray ID:",
        r"cloudflare\.com/5xx",
        r"cf-mitigated",
    ],
    "modsecurity": [
        r"ModSecurity",
        r"OWASP.*CRS",
        r"Request Rejected",
        r"mod_security",
        r"SecRule",
    ],
    "aws_waf": [
        r"Request blocked",
        r"AWS WAF",
        r"x-amzn-RequestId",
        r"You don't have permission",
    ],
    "akamai": [
        r"AkamaiGHost",
        r"Reference.*#[\d.]+",
        r"Access Denied.*Akamai",
    ],
    "sucuri": [
        r"sucuri\.net",
        r"Access Denied.*Sucuri",
        r"Sucuri WebSite Firewall",
    ],
    "f5_bigip": [
        r"BIG-IP",
        r"The requested URL was rejected",
        r"Your support ID is",
    ],
    "barracuda": [
        r"Barracuda",
        r"barra.*firewall",
        r"Web Application Firewall",
    ],
    "imperva": [
        r"Incapsula",
        r"Request unsuccessful",
        r"visid_incap",
        r"Powered by Incapsula",
    ],
    "fortinet": [
        r"FortiWeb",
        r"fortigate",
        r"Fortinet",
    ],
    "citrix": [
        r"Citrix Application Firewall",
        r"ns_af_",
    ],
    "generic": [
        r"Access Denied",
        r"Forbidden",
        r"Request Blocked",
        r"Security Violation",
        r"Your request has been blocked",
        r"Web Application Firewall",
        r"Suspicious activity detected",
        r"Attack detected",
        r"Security check failed",
    ],
}

# Success patterns for vulnerability confirmation
SUCCESS_PATTERNS = {
    PayloadCategory.SQLI: {
        "error_based": [
            r"mysql_fetch|mysqli_",
            r"ORA-\d{5}",
            r"Microsoft OLE DB.*SQL Server",
            r"pg_query|PostgreSQL.*ERROR",
            r"SQLite.*error",
            r"syntax error.*SQL",
            r"unclosed quotation",
            r"quoted string not properly terminated",
        ],
        "content_based": [
            r"admin.*password",
            r"username.*email.*password",
            r"login successful|welcome.*admin",
        ],
    },
    PayloadCategory.XSS: {
        "reflected": [
            r"<script>alert",
            r"onerror=alert",
            r"onload=alert",
            r"javascript:alert",
            r"<svg.*onload",
            r"<img.*onerror",
        ],
    },
    PayloadCategory.CMDI: {
        "linux": [
            r"uid=\d+.*gid=\d+",
            r"root:.*:0:0:",
            r"Linux.*GNU",
            r"/bin/(bash|sh|zsh)",
            r"(drwx|total \d+)",
        ],
        "windows": [
            r"Volume.*Serial Number",
            r"Directory of",
            r"\\\\.*\\\\",
            r"\[fonts\]|\[extensions\]",
            r"OS Name.*Microsoft",
        ],
    },
    PayloadCategory.LFI: {
        "linux": [
            r"root:.*:0:0:",
            r"daemon:.*:\d+:\d+:",
            r"nobody:.*:\d+:\d+:",
            r"Linux version",
            r"PATH=|HOME=|USER=",
        ],
        "windows": [
            r"\[fonts\]",
            r"\[extensions\]",
            r"\[boot loader\]",
            r"localhost.*127\.0\.0\.1",
        ],
    },
    PayloadCategory.SSRF: {
        "cloud_metadata": [
            r"ami-id|instance-id",
            r"compute|vmId",
            r"project/.*instance",
        ],
        "internal": [
            r"localhost|127\.0\.0\.1",
            r"<title>.*[Aa]dmin",
            r"internal",
        ],
    },
    PayloadCategory.XXE: {
        "file_read": [
            r"root:.*:0:0:",
            r"\[fonts\]",
            r"ENTITY.*xxe",
        ],
    },
    PayloadCategory.SSTI: {
        "calculation": [
            r"(?<!\d)49(?!\d)",  # Result of 7*7
            r"7777777",  # String multiplication
        ],
        "config": [
            r"Config|DEBUG|SECRET",
            r"settings\.",
        ],
    },
}


@dataclass
class AnalysisResult:
    """Result of pattern-based analysis."""
    status: TestStatus
    confidence: float
    method: str
    evidence: Optional[str] = None
    waf_signature: Optional[str] = None
    is_ambiguous: bool = False


class PatternAnalyzer:
    """Pattern-based response analyzer."""

    def __init__(self):
        self.logger = logger.bind(component="pattern_analyzer")

    def analyze(
        self,
        result: ExecutionResult,
        payload: Payload,
        baseline: Optional[Dict] = None,
    ) -> AnalysisResult:
        """Analyze response using pattern matching."""
        # Skip if already errored
        if result.error:
            return AnalysisResult(
                status=TestStatus.ERROR,
                confidence=1.0,
                method="error",
                evidence=result.error,
            )

        # Stage 1: Check for WAF block
        waf_result = self._check_waf_block(result)
        if waf_result:
            return waf_result

        # Stage 2: Check for time-based success
        if payload.success_indicator == "time_delay":
            time_result = self._check_time_based(result, payload)
            if time_result:
                return time_result

        # Stage 3: Check for pattern-based success
        pattern_result = self._check_success_patterns(result, payload)
        if pattern_result:
            return pattern_result

        # Stage 4: Check against baseline (content difference)
        if baseline:
            diff_result = self._check_content_diff(result, baseline)
            if diff_result:
                return diff_result

        # Stage 5: No clear indication
        return AnalysisResult(
            status=TestStatus.NOT_VULNERABLE,
            confidence=0.6,
            method="no_match",
            is_ambiguous=True,  # Mark for potential LLM review
        )

    def _check_waf_block(self, result: ExecutionResult) -> Optional[AnalysisResult]:
        """Check if response indicates WAF block."""
        # Status code check
        if result.status_code not in (403, 406, 429, 503):
            return None

        # Check WAF signatures
        combined = f"{result.response_body} {' '.join(f'{k}: {v}' for k, v in result.response_headers.items())}"

        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if re.search(sig, combined, re.I):
                    return AnalysisResult(
                        status=TestStatus.BLOCKED,
                        confidence=0.95,
                        method="waf_signature",
                        evidence=f"WAF signature matched: {sig[:50]}",
                        waf_signature=waf_name,
                    )

        # Generic block without signature
        if result.status_code == 403:
            return AnalysisResult(
                status=TestStatus.BLOCKED,
                confidence=0.8,
                method="status_code",
                evidence=f"HTTP {result.status_code} returned",
                waf_signature="unknown",
            )

        return None

    def _check_time_based(
        self,
        result: ExecutionResult,
        payload: Payload,
    ) -> Optional[AnalysisResult]:
        """Check for time-based injection success."""
        if not payload.expected_delay_ms or not result.response_time_ms:
            return None

        # Allow 10% tolerance
        expected = payload.expected_delay_ms
        tolerance = expected * 0.1
        actual = result.response_time_ms

        if actual >= (expected - tolerance):
            return AnalysisResult(
                status=TestStatus.VULNERABLE,
                confidence=0.85,
                method="time_based",
                evidence=f"Response took {actual}ms (expected {expected}ms)",
            )

        return None

    def _check_success_patterns(
        self,
        result: ExecutionResult,
        payload: Payload,
    ) -> Optional[AnalysisResult]:
        """Check for success pattern match."""
        body = result.response_body

        # Check payload-specific success pattern
        if payload.success_pattern:
            if re.search(payload.success_pattern, body, re.I):
                match = re.search(payload.success_pattern, body, re.I)
                return AnalysisResult(
                    status=TestStatus.VULNERABLE,
                    confidence=0.9,
                    method="payload_pattern",
                    evidence=f"Pattern matched: {match.group()[:100]}",
                )

        # Check category-specific patterns
        category_patterns = SUCCESS_PATTERNS.get(payload.category, {})
        for pattern_group, patterns in category_patterns.items():
            for pattern in patterns:
                if re.search(pattern, body, re.I):
                    match = re.search(pattern, body, re.I)
                    return AnalysisResult(
                        status=TestStatus.VULNERABLE,
                        confidence=0.85,
                        method=f"category_pattern:{pattern_group}",
                        evidence=f"Pattern matched: {match.group()[:100]}",
                    )

        return None

    def _check_content_diff(
        self,
        result: ExecutionResult,
        baseline: Dict,
    ) -> Optional[AnalysisResult]:
        """Check for significant content difference from baseline."""
        baseline_body = baseline.get("response_body", "")
        baseline_length = baseline.get("response_length", 0)
        baseline_status = baseline.get("status_code", 200)

        # Status code changed
        if result.status_code != baseline_status:
            # Don't flag if it went to an error status
            if result.status_code and result.status_code < 400:
                return AnalysisResult(
                    status=TestStatus.VULNERABLE,
                    confidence=0.7,
                    method="status_change",
                    evidence=f"Status changed from {baseline_status} to {result.status_code}",
                    is_ambiguous=True,
                )

        # Significant length change (>20%)
        if baseline_length and result.response_length:
            diff_ratio = abs(result.response_length - baseline_length) / baseline_length
            if diff_ratio > 0.2:
                return AnalysisResult(
                    status=TestStatus.VULNERABLE,
                    confidence=0.6,
                    method="length_change",
                    evidence=f"Response length changed by {diff_ratio:.0%}",
                    is_ambiguous=True,
                )

        return None

    def is_likely_blocked(self, result: ExecutionResult) -> Tuple[bool, Optional[str]]:
        """Quick check if response is likely a WAF block."""
        if result.status_code in (403, 406, 429, 503):
            combined = result.response_body.lower()

            for waf_name, signatures in WAF_SIGNATURES.items():
                for sig in signatures:
                    if re.search(sig, combined, re.I):
                        return True, waf_name

            return True, "unknown"

        return False, None
