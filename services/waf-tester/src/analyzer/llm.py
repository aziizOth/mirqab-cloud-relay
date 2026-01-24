"""
LLM-based response analyzer for ambiguous cases.
Only called when pattern matching is inconclusive (~5% of cases).
"""

import os
import json
from typing import Optional, Dict, Any
from dataclasses import dataclass
import structlog
import httpx

from ..models import Payload, TestStatus
from ..engine.executor import ExecutionResult

logger = structlog.get_logger(__name__)


@dataclass
class LLMAnalysisResult:
    """Result from LLM analysis."""
    status: TestStatus
    confidence: float
    reason: str
    tokens_used: int = 0


class LLMAnalyzer:
    """LLM-based analyzer for ambiguous cases."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-4o-mini",
        api_base: str = "https://api.openai.com/v1",
        timeout: int = 30,
    ):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model
        self.api_base = api_base
        self.timeout = timeout
        self.logger = logger.bind(component="llm_analyzer")
        self._enabled = bool(self.api_key)

        if not self._enabled:
            self.logger.warning("llm_analyzer_disabled", reason="No API key configured")

    @property
    def is_enabled(self) -> bool:
        """Check if LLM analysis is available."""
        return self._enabled

    async def analyze(
        self,
        result: ExecutionResult,
        payload: Payload,
        baseline: Optional[Dict] = None,
    ) -> Optional[LLMAnalysisResult]:
        """Analyze ambiguous response using LLM."""
        if not self._enabled:
            return None

        prompt = self._build_prompt(result, payload, baseline)

        try:
            response = await self._call_api(prompt)
            return self._parse_response(response)

        except Exception as e:
            self.logger.error("llm_analysis_failed", error=str(e))
            return None

    def _build_prompt(
        self,
        result: ExecutionResult,
        payload: Payload,
        baseline: Optional[Dict] = None,
    ) -> str:
        """Build analysis prompt for LLM."""
        # Truncate bodies for cost efficiency
        response_body = result.response_body[:2000] if result.response_body else ""
        baseline_body = ""
        if baseline and baseline.get("response_body"):
            baseline_body = baseline["response_body"][:1000]

        prompt = f"""Analyze if this security test payload was successful.

## Context
- Payload Type: {payload.category.value}
- Payload: {payload.payload}
- Expected Success Pattern: {payload.success_pattern or 'N/A'}

## Response
- Status Code: {result.status_code}
- Response Time: {result.response_time_ms}ms
- Response Length: {result.response_length} bytes

## Response Body (first 2000 chars):
```
{response_body}
```
"""

        if baseline_body:
            prompt += f"""
## Baseline Response (first 1000 chars):
```
{baseline_body}
```
"""

        prompt += """
## Task
Determine if the payload was:
1. **BLOCKED** - A WAF/security control blocked the request
2. **VULNERABLE** - The application is vulnerable (attack succeeded)
3. **NOT_VULNERABLE** - The application handled the payload safely

Consider:
- Error messages that reveal database type or application internals
- Content changes that indicate injection success
- WAF block pages or access denied messages
- Absence of payload reflection (for XSS)
- No significant change from baseline

Respond with ONLY valid JSON (no markdown, no explanation outside JSON):
{"status": "blocked|vulnerable|not_vulnerable", "confidence": 0.0-1.0, "reason": "brief explanation (max 100 chars)"}
"""

        return prompt

    async def _call_api(self, prompt: str) -> Dict[str, Any]:
        """Call LLM API."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        body = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a security testing analyst. Analyze responses to determine if security payloads succeeded. Always respond with valid JSON only."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_tokens": 200,
            "temperature": 0.1,  # Low temperature for consistent analysis
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.api_base}/chat/completions",
                headers=headers,
                json=body,
            )
            response.raise_for_status()
            return response.json()

    def _parse_response(self, response: Dict[str, Any]) -> LLMAnalysisResult:
        """Parse LLM response."""
        try:
            content = response["choices"][0]["message"]["content"]
            usage = response.get("usage", {})
            tokens_used = usage.get("total_tokens", 0)

            # Parse JSON from response
            # Handle potential markdown code blocks
            content = content.strip()
            if content.startswith("```"):
                # Extract JSON from code block
                lines = content.split("\n")
                content = "\n".join(lines[1:-1]) if len(lines) > 2 else ""

            result = json.loads(content)

            # Map status string to enum
            status_map = {
                "blocked": TestStatus.BLOCKED,
                "vulnerable": TestStatus.VULNERABLE,
                "not_vulnerable": TestStatus.NOT_VULNERABLE,
            }
            status = status_map.get(result["status"].lower(), TestStatus.NOT_VULNERABLE)

            return LLMAnalysisResult(
                status=status,
                confidence=float(result.get("confidence", 0.7)),
                reason=result.get("reason", "LLM analysis")[:100],
                tokens_used=tokens_used,
            )

        except (json.JSONDecodeError, KeyError, IndexError) as e:
            self.logger.warning("llm_parse_error", error=str(e))
            return LLMAnalysisResult(
                status=TestStatus.NOT_VULNERABLE,
                confidence=0.5,
                reason=f"Parse error: {str(e)[:50]}",
            )


class MockLLMAnalyzer(LLMAnalyzer):
    """Mock LLM analyzer for testing without API calls."""

    def __init__(self):
        self._enabled = True
        self.logger = logger.bind(component="mock_llm_analyzer")

    async def analyze(
        self,
        result: ExecutionResult,
        payload: Payload,
        baseline: Optional[Dict] = None,
    ) -> Optional[LLMAnalysisResult]:
        """Return mock analysis result."""
        # Simple heuristics to simulate LLM
        if result.status_code in (403, 406, 429):
            return LLMAnalysisResult(
                status=TestStatus.BLOCKED,
                confidence=0.8,
                reason="[MOCK] Status code indicates block",
            )

        if result.response_body and payload.success_pattern:
            import re
            if re.search(payload.success_pattern, result.response_body, re.I):
                return LLMAnalysisResult(
                    status=TestStatus.VULNERABLE,
                    confidence=0.75,
                    reason="[MOCK] Success pattern found",
                )

        return LLMAnalysisResult(
            status=TestStatus.NOT_VULNERABLE,
            confidence=0.6,
            reason="[MOCK] No clear vulnerability indicators",
        )
