"""
Request executor - sends payloads to target with rate limiting.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
import structlog
import httpx

from ..models import Payload, TestStatus
from .selector import PayloadSelection

logger = structlog.get_logger(__name__)


@dataclass
class ExecutionResult:
    """Result of a single payload execution."""
    payload_id: str
    payload: str
    endpoint: str
    parameter: Optional[str]
    param_location: str

    # Response data
    status_code: Optional[int] = None
    response_time_ms: Optional[int] = None
    response_length: Optional[int] = None
    response_body: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)

    # Analysis placeholders (filled by analyzer)
    test_status: TestStatus = TestStatus.ERROR
    waf_signature: Optional[str] = None
    confidence: float = 0.0
    evidence: Optional[str] = None
    analysis_method: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload_id": self.payload_id,
            "payload": self.payload,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "param_location": self.param_location,
            "status_code": self.status_code,
            "response_time_ms": self.response_time_ms,
            "response_length": self.response_length,
            "test_status": self.test_status.value,
            "waf_signature": self.waf_signature,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "analysis_method": self.analysis_method,
            "error": self.error,
        }


class RequestExecutor:
    """Execute payloads against target with rate limiting."""

    def __init__(
        self,
        rate_limit: float = 10.0,  # requests per second
        timeout: int = 10,
        max_response_size: int = 100000,  # 100KB
        follow_redirects: bool = True,
        verify_ssl: bool = False,
    ):
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.max_response_size = max_response_size
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.logger = logger.bind(component="executor")

        # Rate limiting
        self._request_interval = 1.0 / rate_limit
        self._last_request_time = 0.0

    async def execute_selections(
        self,
        base_url: str,
        selections: List[PayloadSelection],
        custom_headers: Optional[Dict[str, str]] = None,
        progress_callback: Optional[callable] = None,
    ) -> List[ExecutionResult]:
        """Execute all payload selections against the target."""
        results = []
        total = sum(len(s.injection_points) for s in selections)
        completed = 0

        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; MirqabWAFTester/1.0)",
            "Accept": "*/*",
        }
        if custom_headers:
            headers.update(custom_headers)

        async with httpx.AsyncClient(
            verify=self.verify_ssl,
            follow_redirects=self.follow_redirects,
            timeout=self.timeout,
        ) as client:
            for selection in selections:
                for injection_point in selection.injection_points:
                    result = await self._execute_single(
                        client=client,
                        base_url=base_url,
                        selection=selection,
                        injection_point=injection_point,
                        headers=headers,
                    )
                    results.append(result)

                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total)

        self.logger.info(
            "execution_complete",
            base_url=base_url,
            total_requests=len(results),
            errors=sum(1 for r in results if r.error),
        )

        return results

    async def _execute_single(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        selection: PayloadSelection,
        injection_point: Dict[str, Any],
        headers: Dict[str, str],
    ) -> ExecutionResult:
        """Execute a single payload against a single injection point."""
        # Rate limiting
        await self._rate_limit()

        payload = selection.payload
        endpoint = injection_point.get("endpoint", "/")
        param_name = injection_point.get("param_name", "id")
        param_location = injection_point.get("param_location", "query")
        method = injection_point.get("method", "GET").upper()

        result = ExecutionResult(
            payload_id=payload.id,
            payload=payload.payload,
            endpoint=endpoint,
            parameter=param_name,
            param_location=param_location,
        )

        try:
            # Build request URL
            url = urljoin(base_url, endpoint)

            # Inject payload based on location
            request_kwargs = {"headers": headers.copy()}

            if param_location == "query":
                # Parse existing query params and add payload
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param_name] = [payload.payload]
                query_string = urlencode(params, doseq=True)
                url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

            elif param_location == "body":
                if method == "GET":
                    method = "POST"
                request_kwargs["data"] = {param_name: payload.payload}

            elif param_location == "header":
                request_kwargs["headers"][param_name] = payload.payload

            elif param_location == "cookie":
                request_kwargs["cookies"] = {param_name: payload.payload}

            # Execute request
            start_time = time.time()

            if method == "GET":
                response = await client.get(url, **request_kwargs)
            elif method == "POST":
                response = await client.post(url, **request_kwargs)
            elif method == "PUT":
                response = await client.put(url, **request_kwargs)
            else:
                response = await client.request(method, url, **request_kwargs)

            elapsed_ms = int((time.time() - start_time) * 1000)

            # Capture response
            result.status_code = response.status_code
            result.response_time_ms = elapsed_ms
            result.response_headers = dict(response.headers)

            # Truncate response body
            body = response.text
            if len(body) > self.max_response_size:
                body = body[:self.max_response_size] + "...[TRUNCATED]"
            result.response_body = body
            result.response_length = len(response.content)

            self.logger.debug(
                "request_executed",
                payload_id=payload.id,
                url=url,
                status_code=response.status_code,
                elapsed_ms=elapsed_ms,
            )

        except httpx.TimeoutException:
            result.error = "Request timeout"
            result.test_status = TestStatus.TIMEOUT
            self.logger.warning(
                "request_timeout",
                payload_id=payload.id,
                endpoint=endpoint,
            )

        except Exception as e:
            result.error = str(e)
            result.test_status = TestStatus.ERROR
            self.logger.warning(
                "request_error",
                payload_id=payload.id,
                endpoint=endpoint,
                error=str(e),
            )

        return result

    async def _rate_limit(self):
        """Apply rate limiting between requests."""
        current_time = time.time()
        elapsed = current_time - self._last_request_time

        if elapsed < self._request_interval:
            await asyncio.sleep(self._request_interval - elapsed)

        self._last_request_time = time.time()

    async def execute_baseline(
        self,
        url: str,
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Execute baseline request without payload for comparison."""
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; MirqabWAFTester/1.0)",
        }
        if custom_headers:
            headers.update(custom_headers)

        async with httpx.AsyncClient(
            verify=self.verify_ssl,
            follow_redirects=self.follow_redirects,
            timeout=self.timeout,
        ) as client:
            try:
                start_time = time.time()
                response = await client.get(url, headers=headers)
                elapsed_ms = int((time.time() - start_time) * 1000)

                return {
                    "url": url,
                    "status_code": response.status_code,
                    "response_time_ms": elapsed_ms,
                    "response_length": len(response.content),
                    "response_body": response.text[:self.max_response_size],
                    "response_headers": dict(response.headers),
                }

            except Exception as e:
                return {
                    "url": url,
                    "error": str(e),
                }

    async def quick_test(
        self,
        url: str,
        payload: str,
        param_name: str = "q",
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> ExecutionResult:
        """Quick test with a single payload."""
        # Create a minimal selection
        class MockPayload:
            id = "quick-test"
            payload = payload

        selection = PayloadSelection(
            payload=MockPayload(),
            injection_points=[{
                "endpoint": "/",
                "method": "GET",
                "param_name": param_name,
                "param_location": "query",
            }],
        )

        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; MirqabWAFTester/1.0)",
        }
        if custom_headers:
            headers.update(custom_headers)

        async with httpx.AsyncClient(
            verify=self.verify_ssl,
            follow_redirects=self.follow_redirects,
            timeout=self.timeout,
        ) as client:
            return await self._execute_single(
                client=client,
                base_url=url,
                selection=selection,
                injection_point=selection.injection_points[0],
                headers=headers,
            )
