"""
Payload selector - context-aware payload selection.
"""

from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
import structlog

from ..models import Payload, PayloadCategory, TargetOS
from ..discovery.fingerprint import TargetContext
from ..payloads.database import PayloadDatabase

logger = structlog.get_logger(__name__)


@dataclass
class PayloadSelection:
    """Selected payloads with injection points."""
    payload: Payload
    injection_points: List[Dict[str, Any]] = field(default_factory=list)
    encoding: Optional[str] = None
    score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload_id": self.payload.id,
            "payload": self.payload.payload,
            "category": self.payload.category.value,
            "injection_points": self.injection_points,
            "encoding": self.encoding,
            "score": self.score,
        }


class PayloadSelector:
    """Context-aware payload selector."""

    def __init__(self, payload_db: PayloadDatabase):
        self.payload_db = payload_db
        self.logger = logger.bind(component="payload_selector")

    def select_payloads(
        self,
        category: PayloadCategory,
        context: TargetContext,
        max_payloads: int = 50,
        include_bypass: bool = True,
    ) -> List[PayloadSelection]:
        """Select and prepare payloads for the target context."""
        # Get relevant payloads from database
        payloads = self.payload_db.get_payloads_for_context(
            category=category,
            context=context,
            max_payloads=max_payloads,
            include_bypass=include_bypass,
        )

        # Build selections with injection points
        selections = []
        for payload in payloads:
            selection = self._build_selection(payload, context)
            selections.append(selection)

        self.logger.info(
            "payloads_selected",
            category=category.value,
            context_tech=context.tech,
            context_os=context.os,
            selected_count=len(selections),
        )

        return selections

    def _build_selection(
        self,
        payload: Payload,
        context: TargetContext,
    ) -> PayloadSelection:
        """Build a payload selection with injection points."""
        injection_points = []

        # Determine injection points from discovered endpoints/params
        if context.endpoints:
            for endpoint in context.endpoints:
                params = endpoint.get("parameters", [])
                for param in params:
                    # Check if param location matches payload target
                    param_location = param.get("location", "query")
                    target_location = payload.target_param_location

                    if target_location == "any" or target_location == param_location:
                        injection_points.append({
                            "endpoint": endpoint.get("path", "/"),
                            "method": endpoint.get("method", "GET"),
                            "param_name": param.get("name"),
                            "param_location": param_location,
                        })

        # If no endpoints discovered, use default injection points
        if not injection_points:
            injection_points = self._get_default_injection_points()

        # Calculate relevance score
        score = self._calculate_score(payload, context)

        return PayloadSelection(
            payload=payload,
            injection_points=injection_points,
            encoding=self._determine_encoding(payload, context),
            score=score,
        )

    def _get_default_injection_points(self) -> List[Dict[str, Any]]:
        """Get default injection points when none discovered."""
        return [
            {"endpoint": "/", "method": "GET", "param_name": "id", "param_location": "query"},
            {"endpoint": "/", "method": "GET", "param_name": "q", "param_location": "query"},
            {"endpoint": "/", "method": "GET", "param_name": "search", "param_location": "query"},
            {"endpoint": "/", "method": "GET", "param_name": "page", "param_location": "query"},
            {"endpoint": "/", "method": "GET", "param_name": "file", "param_location": "query"},
            {"endpoint": "/", "method": "GET", "param_name": "url", "param_location": "query"},
        ]

    def _calculate_score(self, payload: Payload, context: TargetContext) -> float:
        """Calculate relevance score for payload."""
        score = 50.0

        # Technology match
        if context.tech:
            target_techs = payload.target_tech or []
            if context.tech in target_techs:
                score += 40
            elif "generic" in target_techs:
                score += 20

        # Database match (for SQLi)
        if context.db and payload.category == PayloadCategory.SQLI:
            target_techs = payload.target_tech or []
            if context.db in target_techs:
                score += 40
            elif "generic" in target_techs:
                score += 15

        # OS match
        if context.os:
            if payload.target_os == TargetOS.BOTH:
                score += 15
            elif (context.os == "linux" and payload.target_os == TargetOS.LINUX) or \
                 (context.os == "windows" and payload.target_os == TargetOS.WINDOWS):
                score += 30

        # WAF bypass bonus
        if context.waf and payload.subcategory == "bypass":
            score += 25

        return score

    def _determine_encoding(
        self,
        payload: Payload,
        context: TargetContext,
    ) -> Optional[str]:
        """Determine if special encoding should be used."""
        # If WAF detected, try URL encoding variants
        if context.waf:
            if payload.encoded_variants:
                if "double_url" in payload.encoded_variants:
                    return "double_url"
                elif "url" in payload.encoded_variants:
                    return "url"
        return None

    def select_all_categories(
        self,
        context: TargetContext,
        categories: Optional[List[PayloadCategory]] = None,
        max_per_category: int = 20,
        include_bypass: bool = True,
    ) -> Dict[PayloadCategory, List[PayloadSelection]]:
        """Select payloads for multiple categories."""
        if categories is None:
            categories = list(PayloadCategory)

        result = {}
        for category in categories:
            selections = self.select_payloads(
                category=category,
                context=context,
                max_payloads=max_per_category,
                include_bypass=include_bypass,
            )
            if selections:
                result[category] = selections

        return result

    def get_category_recommendations(
        self,
        context: TargetContext,
    ) -> List[Dict[str, Any]]:
        """Get recommended attack categories based on target context."""
        recommendations = []

        # SQLi recommendations
        if context.db or context.tech in ["php", "asp", "asp.net", "java"]:
            recommendations.append({
                "category": PayloadCategory.SQLI.value,
                "confidence": 0.9 if context.db else 0.7,
                "reason": f"Database detected: {context.db}" if context.db else "Technology likely uses database",
            })

        # XSS always relevant for web apps
        recommendations.append({
            "category": PayloadCategory.XSS.value,
            "confidence": 0.95,
            "reason": "XSS testing applicable to all web applications",
        })

        # Command injection for PHP, Python, Perl
        if context.tech in ["php", "python", "perl", "ruby"]:
            recommendations.append({
                "category": PayloadCategory.CMDI.value,
                "confidence": 0.8,
                "reason": f"{context.tech} applications may use system commands",
            })

        # LFI for PHP particularly
        if context.tech == "php":
            recommendations.append({
                "category": PayloadCategory.LFI.value,
                "confidence": 0.85,
                "reason": "PHP applications commonly vulnerable to LFI",
            })

        # SSTI for template engines
        if context.tech in ["python", "java", "ruby", "php"]:
            if context.framework in ["django", "flask", "spring", "rails", "laravel"]:
                recommendations.append({
                    "category": PayloadCategory.SSTI.value,
                    "confidence": 0.8,
                    "reason": f"{context.framework} uses templates",
                })

        # XXE for XML-processing applications
        if context.tech in ["java", "php"]:
            recommendations.append({
                "category": PayloadCategory.XXE.value,
                "confidence": 0.6,
                "reason": f"{context.tech} may process XML",
            })

        # SSRF when URL parameters detected
        if context.parameters:
            url_params = [p for p in context.parameters if "url" in str(p).lower()]
            if url_params:
                recommendations.append({
                    "category": PayloadCategory.SSRF.value,
                    "confidence": 0.85,
                    "reason": "URL parameters detected in application",
                })

        # Sort by confidence
        recommendations.sort(key=lambda x: x["confidence"], reverse=True)

        return recommendations
