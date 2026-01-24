"""
Payload database with context-aware querying.
"""

from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import or_
import structlog

from ..models import Payload, PayloadCategory, TargetOS
from ..discovery.fingerprint import TargetContext

logger = structlog.get_logger(__name__)


class PayloadDatabase:
    """Context-aware payload database."""

    def __init__(self, session: Session):
        self.session = session
        self.logger = logger.bind(component="payload_db")

    def get_payloads_for_context(
        self,
        category: PayloadCategory,
        context: TargetContext,
        max_payloads: int = 50,
        include_bypass: bool = True,
    ) -> List[Payload]:
        """Get payloads relevant to the target context."""
        query = self.session.query(Payload).filter(
            Payload.category == category,
            Payload.is_harmless == True,
        )

        # Filter by OS if known
        if context.os:
            os_enum = TargetOS.LINUX if context.os == "linux" else TargetOS.WINDOWS
            query = query.filter(
                or_(
                    Payload.target_os == os_enum,
                    Payload.target_os == TargetOS.BOTH,
                )
            )

        # Exclude bypass variants if not wanted
        if not include_bypass:
            query = query.filter(
                or_(
                    Payload.subcategory.is_(None),
                    Payload.subcategory != "bypass",
                )
            )

        # Get all matching payloads
        payloads = query.all()

        # Score and sort by relevance
        scored = []
        for payload in payloads:
            score = self._score_payload(payload, context)
            scored.append((score, payload))

        # Sort by score descending
        scored.sort(key=lambda x: x[0], reverse=True)

        # Return top N
        result = [p for _, p in scored[:max_payloads]]

        self.logger.debug(
            "payloads_selected",
            category=category.value,
            context_tech=context.tech,
            context_db=context.db,
            total_matching=len(payloads),
            selected=len(result),
        )

        return result

    def _score_payload(self, payload: Payload, context: TargetContext) -> float:
        """Score payload relevance for the target context."""
        score = 50.0  # Base score

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

        # WAF bypass bonus if WAF detected
        if context.waf and payload.subcategory == "bypass":
            score += 25

        return score

    def get_all_by_category(
        self,
        category: PayloadCategory,
        include_bypass: bool = True,
    ) -> List[Payload]:
        """Get all payloads for a category."""
        query = self.session.query(Payload).filter(
            Payload.category == category,
            Payload.is_harmless == True,
        )

        if not include_bypass:
            query = query.filter(
                or_(
                    Payload.subcategory.is_(None),
                    Payload.subcategory != "bypass",
                )
            )

        return query.all()

    def get_by_id(self, payload_id: str) -> Optional[Payload]:
        """Get a specific payload by ID."""
        return self.session.query(Payload).filter(Payload.id == payload_id).first()

    def get_categories(self) -> List[str]:
        """Get all available categories."""
        return [c.value for c in PayloadCategory]

    def get_stats(self) -> Dict[str, Any]:
        """Get payload database statistics."""
        total = self.session.query(Payload).count()

        by_category = {}
        for category in PayloadCategory:
            count = self.session.query(Payload).filter(
                Payload.category == category
            ).count()
            by_category[category.value] = count

        by_os = {
            "linux": self.session.query(Payload).filter(
                Payload.target_os == TargetOS.LINUX
            ).count(),
            "windows": self.session.query(Payload).filter(
                Payload.target_os == TargetOS.WINDOWS
            ).count(),
            "both": self.session.query(Payload).filter(
                Payload.target_os == TargetOS.BOTH
            ).count(),
        }

        bypass_count = self.session.query(Payload).filter(
            Payload.subcategory == "bypass"
        ).count()

        return {
            "total": total,
            "by_category": by_category,
            "by_os": by_os,
            "bypass_variants": bypass_count,
        }

    def search(
        self,
        query: str,
        category: Optional[PayloadCategory] = None,
        limit: int = 50,
    ) -> List[Payload]:
        """Search payloads by content or description."""
        q = self.session.query(Payload).filter(
            or_(
                Payload.payload.ilike(f"%{query}%"),
                Payload.description.ilike(f"%{query}%"),
                Payload.id.ilike(f"%{query}%"),
            )
        )

        if category:
            q = q.filter(Payload.category == category)

        return q.limit(limit).all()
