"""
Combined response analyzer - Pattern matching with LLM fallback.
"""

from typing import Optional, Dict, List
import structlog

from ..models import Payload, TestStatus
from ..engine.executor import ExecutionResult
from .patterns import PatternAnalyzer, AnalysisResult
from .llm import LLMAnalyzer, MockLLMAnalyzer

logger = structlog.get_logger(__name__)


class ResponseAnalyzer:
    """Combined response analyzer with pattern matching and LLM fallback."""

    def __init__(
        self,
        use_llm: bool = True,
        llm_api_key: Optional[str] = None,
        llm_model: str = "gpt-4o-mini",
    ):
        self.pattern_analyzer = PatternAnalyzer()
        self.use_llm = use_llm
        self.logger = logger.bind(component="response_analyzer")

        # Initialize LLM analyzer
        if use_llm:
            if llm_api_key:
                self.llm_analyzer = LLMAnalyzer(
                    api_key=llm_api_key,
                    model=llm_model,
                )
            else:
                self.llm_analyzer = LLMAnalyzer()  # Will try env var

            if not self.llm_analyzer.is_enabled:
                self.logger.info("llm_fallback_disabled", reason="No API key")
                self.llm_analyzer = MockLLMAnalyzer()
        else:
            self.llm_analyzer = None

        # Statistics
        self._stats = {
            "total_analyzed": 0,
            "pattern_matched": 0,
            "llm_fallback": 0,
            "blocked": 0,
            "vulnerable": 0,
            "not_vulnerable": 0,
            "errors": 0,
        }

    async def analyze(
        self,
        result: ExecutionResult,
        payload: Payload,
        baseline: Optional[Dict] = None,
    ) -> ExecutionResult:
        """Analyze response and update result with findings."""
        self._stats["total_analyzed"] += 1

        # Stage 1: Pattern-based analysis (free, instant)
        analysis = self.pattern_analyzer.analyze(result, payload, baseline)

        # Stage 2: If ambiguous and LLM enabled, use LLM fallback
        if analysis.is_ambiguous and self.llm_analyzer and self.use_llm:
            self._stats["llm_fallback"] += 1
            self.logger.debug(
                "llm_fallback_triggered",
                payload_id=payload.id,
                pattern_status=analysis.status.value,
                pattern_confidence=analysis.confidence,
            )

            llm_result = await self.llm_analyzer.analyze(result, payload, baseline)
            if llm_result:
                # Use LLM result if confidence is higher
                if llm_result.confidence > analysis.confidence:
                    analysis = AnalysisResult(
                        status=llm_result.status,
                        confidence=llm_result.confidence,
                        method=f"llm_analysis",
                        evidence=llm_result.reason,
                        waf_signature=analysis.waf_signature,
                    )
        else:
            self._stats["pattern_matched"] += 1

        # Update result with analysis
        result.test_status = analysis.status
        result.confidence = analysis.confidence
        result.analysis_method = analysis.method
        result.evidence = analysis.evidence
        result.waf_signature = analysis.waf_signature

        # Update stats
        if analysis.status == TestStatus.BLOCKED:
            self._stats["blocked"] += 1
        elif analysis.status == TestStatus.VULNERABLE:
            self._stats["vulnerable"] += 1
        elif analysis.status == TestStatus.NOT_VULNERABLE:
            self._stats["not_vulnerable"] += 1
        elif analysis.status == TestStatus.ERROR:
            self._stats["errors"] += 1

        return result

    async def analyze_batch(
        self,
        results: List[ExecutionResult],
        payloads: Dict[str, Payload],
        baseline: Optional[Dict] = None,
    ) -> List[ExecutionResult]:
        """Analyze a batch of results."""
        analyzed = []

        for result in results:
            payload = payloads.get(result.payload_id)
            if payload:
                analyzed_result = await self.analyze(result, payload, baseline)
                analyzed.append(analyzed_result)
            else:
                # No payload found, mark as error
                result.test_status = TestStatus.ERROR
                result.evidence = "Payload definition not found"
                analyzed.append(result)

        return analyzed

    def get_stats(self) -> Dict:
        """Get analysis statistics."""
        total = self._stats["total_analyzed"]
        return {
            **self._stats,
            "pattern_match_rate": (
                self._stats["pattern_matched"] / total if total > 0 else 0
            ),
            "llm_fallback_rate": (
                self._stats["llm_fallback"] / total if total > 0 else 0
            ),
            "block_rate": (
                self._stats["blocked"] / total if total > 0 else 0
            ),
            "vulnerability_rate": (
                self._stats["vulnerable"] / total if total > 0 else 0
            ),
        }

    def reset_stats(self):
        """Reset analysis statistics."""
        self._stats = {
            "total_analyzed": 0,
            "pattern_matched": 0,
            "llm_fallback": 0,
            "blocked": 0,
            "vulnerable": 0,
            "not_vulnerable": 0,
            "errors": 0,
        }
