"""
Simple web crawler for endpoint and parameter discovery.
Used in URL mode when no agent is available.
"""

import re
import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
from urllib.parse import urljoin, urlparse, parse_qs
import structlog
import httpx
from bs4 import BeautifulSoup

logger = structlog.get_logger(__name__)


@dataclass
class DiscoveredEndpoint:
    """Discovered endpoint with parameters."""
    path: str
    method: str = "GET"
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    content_type: Optional[str] = None
    requires_auth: bool = False

    def to_dict(self) -> Dict[str, Any]:
        # Convert parameters to dicts if they're DiscoveredParameter objects
        params = []
        for p in self.parameters:
            if hasattr(p, 'to_dict'):
                params.append(p.to_dict())
            elif isinstance(p, dict):
                params.append(p)
            else:
                params.append({"name": str(p)})
        return {
            "path": self.path,
            "method": self.method,
            "parameters": params,
            "content_type": self.content_type,
            "requires_auth": self.requires_auth,
        }


@dataclass
class DiscoveredParameter:
    """Discovered parameter."""
    name: str
    location: str  # query, body, header, cookie
    param_type: str = "string"  # string, integer, email, etc.
    sample_value: Optional[str] = None
    required: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "type": self.param_type,
            "sample_value": self.sample_value,
            "required": self.required,
        }


class Crawler:
    """Simple web crawler for endpoint discovery."""

    def __init__(
        self,
        max_depth: int = 3,
        max_pages: int = 100,
        rate_limit: float = 0.5,
        timeout: int = 10,
    ):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.logger = logger.bind(component="crawler")

    async def crawl(
        self,
        start_url: str,
        custom_headers: Dict[str, str] = None,
    ) -> tuple[List[DiscoveredEndpoint], List[DiscoveredParameter]]:
        """Crawl website to discover endpoints and parameters."""
        parsed = urlparse(start_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        visited: Set[str] = set()
        to_visit: List[tuple[str, int]] = [(start_url, 0)]
        endpoints: Dict[str, DiscoveredEndpoint] = {}
        parameters: Dict[str, DiscoveredParameter] = {}

        headers = {"User-Agent": "Mozilla/5.0 (compatible; MirqabWAFTester/1.0)"}
        if custom_headers:
            headers.update(custom_headers)

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=self.timeout,
        ) as client:
            while to_visit and len(visited) < self.max_pages:
                url, depth = to_visit.pop(0)

                if url in visited or depth > self.max_depth:
                    continue

                visited.add(url)

                try:
                    response = await client.get(url, headers=headers)
                    await asyncio.sleep(self.rate_limit)

                    # Parse HTML
                    soup = BeautifulSoup(response.text, "html.parser")

                    # Extract links
                    links = self._extract_links(soup, base_url, url)
                    for link in links:
                        if link not in visited:
                            to_visit.append((link, depth + 1))

                    # Extract forms
                    forms = self._extract_forms(soup, base_url, url)
                    for endpoint in forms:
                        endpoints[endpoint.path] = endpoint
                        for param in endpoint.parameters:
                            param_key = f"{endpoint.path}:{param['name']}"
                            parameters[param_key] = DiscoveredParameter(
                                name=param["name"],
                                location=param["location"],
                                param_type=param.get("type", "string"),
                                sample_value=param.get("sample_value"),
                                required=param.get("required", False),
                            )

                    # Extract URL parameters
                    url_params = self._extract_url_params(url)
                    for param in url_params:
                        param_key = f"{urlparse(url).path}:{param.name}"
                        parameters[param_key] = param

                    # Add endpoint for this URL
                    path = urlparse(url).path or "/"
                    if path not in endpoints:
                        endpoints[path] = DiscoveredEndpoint(
                            path=path,
                            method="GET",
                            parameters=url_params,
                        )

                    self.logger.debug(
                        "page_crawled",
                        url=url,
                        depth=depth,
                        links_found=len(links),
                    )

                except httpx.TimeoutException:
                    self.logger.warning("crawl_timeout", url=url)
                except Exception as e:
                    self.logger.warning("crawl_error", url=url, error=str(e))

        self.logger.info(
            "crawl_complete",
            start_url=start_url,
            pages_visited=len(visited),
            endpoints_found=len(endpoints),
            parameters_found=len(parameters),
        )

        return (
            list(endpoints.values()),
            list(parameters.values()),
        )

    def _extract_links(
        self,
        soup: BeautifulSoup,
        base_url: str,
        current_url: str,
    ) -> List[str]:
        """Extract internal links from page."""
        links = []
        current_domain = urlparse(current_url).netloc

        for tag in soup.find_all(["a", "link"]):
            href = tag.get("href")
            if not href:
                continue

            # Skip anchors, javascript, mailto
            if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue

            # Build absolute URL
            absolute = urljoin(current_url, href)
            parsed = urlparse(absolute)

            # Only same domain
            if parsed.netloc != current_domain:
                continue

            # Normalize
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if normalized not in links:
                links.append(normalized)

        return links

    def _extract_forms(
        self,
        soup: BeautifulSoup,
        base_url: str,
        current_url: str,
    ) -> List[DiscoveredEndpoint]:
        """Extract forms and their parameters."""
        endpoints = []

        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()

            # Build form URL
            if action:
                form_url = urljoin(current_url, action)
            else:
                form_url = current_url

            path = urlparse(form_url).path or "/"

            # Extract form inputs
            parameters = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue

                param_type = "string"
                inp_type = inp.get("type", "text")

                if inp_type == "email":
                    param_type = "email"
                elif inp_type == "number":
                    param_type = "integer"
                elif inp_type == "password":
                    param_type = "password"
                elif inp_type == "hidden":
                    param_type = "hidden"

                parameters.append({
                    "name": name,
                    "location": "body" if method == "POST" else "query",
                    "type": param_type,
                    "sample_value": inp.get("value"),
                    "required": inp.get("required") is not None,
                })

            content_type = "application/x-www-form-urlencoded"
            if form.get("enctype"):
                content_type = form.get("enctype")

            endpoints.append(DiscoveredEndpoint(
                path=path,
                method=method,
                parameters=parameters,
                content_type=content_type,
            ))

        return endpoints

    def _extract_url_params(self, url: str) -> List[DiscoveredParameter]:
        """Extract parameters from URL query string."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        result = []
        for name, values in params.items():
            param_type = self._guess_param_type(name, values[0] if values else "")
            result.append(DiscoveredParameter(
                name=name,
                location="query",
                param_type=param_type,
                sample_value=values[0] if values else None,
            ))

        return result

    def _guess_param_type(self, name: str, value: str) -> str:
        """Guess parameter type from name and value."""
        name_lower = name.lower()

        # Name-based guessing
        if any(x in name_lower for x in ["id", "num", "count", "page", "limit", "offset"]):
            return "integer"
        if any(x in name_lower for x in ["email", "mail"]):
            return "email"
        if any(x in name_lower for x in ["url", "uri", "link", "href"]):
            return "url"
        if any(x in name_lower for x in ["date", "time", "timestamp"]):
            return "datetime"

        # Value-based guessing
        if value:
            if value.isdigit():
                return "integer"
            if re.match(r"^[\w.+-]+@[\w.-]+\.\w+$", value):
                return "email"
            if re.match(r"^https?://", value):
                return "url"

        return "string"

    async def quick_discover(
        self,
        url: str,
        custom_headers: Dict[str, str] = None,
    ) -> tuple[List[DiscoveredEndpoint], List[DiscoveredParameter]]:
        """Quick discovery - just analyze the given URL without deep crawling."""
        endpoints = []
        parameters = []

        headers = {"User-Agent": "Mozilla/5.0 (compatible; MirqabWAFTester/1.0)"}
        if custom_headers:
            headers.update(custom_headers)

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=self.timeout,
        ) as client:
            try:
                response = await client.get(url, headers=headers)

                # Extract URL params
                url_params = self._extract_url_params(url)
                parameters.extend(url_params)

                # Parse page
                soup = BeautifulSoup(response.text, "html.parser")

                # Extract forms
                forms = self._extract_forms(soup, url, url)
                endpoints.extend(forms)

                # Add common test params if none found
                if not parameters:
                    parameters = [
                        DiscoveredParameter(name="id", location="query", param_type="integer"),
                        DiscoveredParameter(name="q", location="query", param_type="string"),
                        DiscoveredParameter(name="search", location="query", param_type="string"),
                        DiscoveredParameter(name="page", location="query", param_type="integer"),
                    ]

                # Add base endpoint
                path = urlparse(url).path or "/"
                if not any(e.path == path for e in endpoints):
                    endpoints.append(DiscoveredEndpoint(
                        path=path,
                        method="GET",
                        parameters=[p.to_dict() for p in url_params],
                    ))

            except Exception as e:
                self.logger.warning("quick_discover_error", url=url, error=str(e))

        return endpoints, parameters
