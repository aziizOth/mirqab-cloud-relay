"""
Crucible EDR Integration - External EDR/AV API Clients

Integrates with EDR/AV platforms to:
- Query detection events
- Retrieve detailed threat information
- Correlate internal test results with EDR telemetry
- Verify detection effectiveness

Supported platforms:
- CrowdStrike Falcon
- SentinelOne
- Microsoft Defender for Endpoint
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

import aiohttp

logger = logging.getLogger(__name__)


class DetectionSeverity(Enum):
    """Standardized detection severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DetectionEvent:
    """Standardized detection event across EDR platforms."""

    event_id: str
    source: str  # EDR platform name
    timestamp: datetime
    severity: DetectionSeverity
    detection_type: str  # signature, behavioral, ML, etc.
    threat_name: str
    threat_description: str = ""
    host_name: Optional[str] = None
    host_id: Optional[str] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    process_id: Optional[int] = None
    process_hash: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    command_line: Optional[str] = None
    user_name: Optional[str] = None
    action_taken: str = "none"  # blocked, quarantined, allowed, etc.
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)


class EDRClient(ABC):
    """Abstract base class for EDR platform clients."""

    @property
    @abstractmethod
    def platform_name(self) -> str:
        """Return the EDR platform name."""
        pass

    @abstractmethod
    async def authenticate(self) -> bool:
        """Authenticate with the EDR API."""
        pass

    @abstractmethod
    async def get_detections(
        self,
        start_time: datetime,
        end_time: Optional[datetime] = None,
        host_id: Optional[str] = None,
    ) -> list[DetectionEvent]:
        """Query detections within a time range."""
        pass

    @abstractmethod
    async def get_detection_details(self, detection_id: str) -> Optional[DetectionEvent]:
        """Get detailed information about a specific detection."""
        pass

    @abstractmethod
    async def get_host_status(self, host_id: str) -> dict:
        """Get current status of a host."""
        pass


class CrowdStrikeClient(EDRClient):
    """
    CrowdStrike Falcon API client.

    Uses OAuth2 authentication with client credentials.
    API documentation: https://falcon.crowdstrike.com/documentation
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str = "https://api.crowdstrike.com",
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url
        self._access_token: Optional[str] = None
        self._token_expires: Optional[datetime] = None
        self._session: Optional[aiohttp.ClientSession] = None

    @property
    def platform_name(self) -> str:
        return "CrowdStrike Falcon"

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def authenticate(self) -> bool:
        """Authenticate using OAuth2 client credentials."""
        try:
            session = await self._get_session()

            async with session.post(
                f"{self.base_url}/oauth2/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
            ) as resp:
                if resp.status != 201:
                    logger.error(f"CrowdStrike auth failed: {resp.status}")
                    return False

                data = await resp.json()
                self._access_token = data["access_token"]
                self._token_expires = datetime.now(timezone.utc) + timedelta(
                    seconds=data["expires_in"] - 60
                )

                logger.info("CrowdStrike authentication successful")
                return True

        except Exception as e:
            logger.error(f"CrowdStrike auth error: {e}")
            return False

    async def _ensure_authenticated(self) -> None:
        """Ensure we have a valid access token."""
        if (
            not self._access_token or
            not self._token_expires or
            datetime.now(timezone.utc) >= self._token_expires
        ):
            success = await self.authenticate()
            if not success:
                raise RuntimeError("Failed to authenticate with CrowdStrike")

    async def _api_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        json_data: Optional[dict] = None,
    ) -> dict:
        """Make authenticated API request."""
        await self._ensure_authenticated()
        session = await self._get_session()

        headers = {"Authorization": f"Bearer {self._access_token}"}

        async with session.request(
            method,
            f"{self.base_url}{endpoint}",
            params=params,
            json=json_data,
            headers=headers,
        ) as resp:
            if resp.status == 401:
                # Token expired, retry
                self._access_token = None
                await self._ensure_authenticated()
                return await self._api_request(method, endpoint, params, json_data)

            resp.raise_for_status()
            return await resp.json()

    async def get_detections(
        self,
        start_time: datetime,
        end_time: Optional[datetime] = None,
        host_id: Optional[str] = None,
    ) -> list[DetectionEvent]:
        """Query CrowdStrike detections."""
        end_time = end_time or datetime.now(timezone.utc)

        # Build FQL filter
        filter_parts = [
            f"first_behavior:>='{start_time.strftime('%Y-%m-%dT%H:%M:%SZ')}'",
            f"first_behavior:<='{end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}'",
        ]
        if host_id:
            filter_parts.append(f"device.device_id:'{host_id}'")

        fql_filter = "+".join(filter_parts)

        # Get detection IDs
        ids_response = await self._api_request(
            "GET",
            "/detects/queries/detects/v1",
            params={"filter": fql_filter, "limit": 100},
        )

        detection_ids = ids_response.get("resources", [])
        if not detection_ids:
            return []

        # Get detection details
        details_response = await self._api_request(
            "POST",
            "/detects/entities/summaries/GET/v1",
            json_data={"ids": detection_ids},
        )

        detections = []
        for det in details_response.get("resources", []):
            detections.append(self._parse_detection(det))

        return detections

    async def get_detection_details(self, detection_id: str) -> Optional[DetectionEvent]:
        """Get detailed detection information."""
        try:
            response = await self._api_request(
                "POST",
                "/detects/entities/summaries/GET/v1",
                json_data={"ids": [detection_id]},
            )

            resources = response.get("resources", [])
            if resources:
                return self._parse_detection(resources[0])
            return None

        except Exception as e:
            logger.error(f"Failed to get detection details: {e}")
            return None

    async def get_host_status(self, host_id: str) -> dict:
        """Get host status from CrowdStrike."""
        try:
            response = await self._api_request(
                "GET",
                f"/devices/entities/devices/v2",
                params={"ids": host_id},
            )

            resources = response.get("resources", [])
            if resources:
                device = resources[0]
                return {
                    "host_id": device.get("device_id"),
                    "hostname": device.get("hostname"),
                    "status": device.get("status"),
                    "last_seen": device.get("last_seen"),
                    "platform": device.get("platform_name"),
                    "os_version": device.get("os_version"),
                    "agent_version": device.get("agent_version"),
                }
            return {}

        except Exception as e:
            logger.error(f"Failed to get host status: {e}")
            return {}

    def _parse_detection(self, data: dict) -> DetectionEvent:
        """Parse CrowdStrike detection into standardized format."""
        behaviors = data.get("behaviors", [{}])
        first_behavior = behaviors[0] if behaviors else {}

        severity_map = {
            1: DetectionSeverity.INFO,
            2: DetectionSeverity.LOW,
            3: DetectionSeverity.MEDIUM,
            4: DetectionSeverity.HIGH,
            5: DetectionSeverity.CRITICAL,
        }

        return DetectionEvent(
            event_id=data.get("detection_id", ""),
            source=self.platform_name,
            timestamp=datetime.fromisoformat(
                data.get("first_behavior", datetime.now(timezone.utc).isoformat()).replace("Z", "+00:00")
            ),
            severity=severity_map.get(data.get("max_severity", 1), DetectionSeverity.INFO),
            detection_type=first_behavior.get("pattern_disposition_details", {}).get("detection_type", "unknown"),
            threat_name=first_behavior.get("display_name", "Unknown Threat"),
            threat_description=first_behavior.get("description", ""),
            host_name=data.get("device", {}).get("hostname"),
            host_id=data.get("device", {}).get("device_id"),
            process_name=first_behavior.get("filename"),
            process_path=first_behavior.get("filepath"),
            process_id=first_behavior.get("parent_details", {}).get("parent_pid"),
            process_hash=first_behavior.get("sha256"),
            command_line=first_behavior.get("cmdline"),
            user_name=first_behavior.get("user_name"),
            action_taken=data.get("status", ""),
            mitre_tactics=[t.get("tactic", "") for t in first_behavior.get("tactics_and_techniques", [])],
            mitre_techniques=[t.get("technique", "") for t in first_behavior.get("tactics_and_techniques", [])],
            raw_data=data,
        )

    async def close(self) -> None:
        """Close HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()


class SentinelOneClient(EDRClient):
    """
    SentinelOne API client.

    Uses API token authentication.
    API documentation: https://developer.sentinelone.com/
    """

    def __init__(
        self,
        api_token: str,
        base_url: str,  # e.g., https://usea1-partners.sentinelone.net
    ):
        self.api_token = api_token
        self.base_url = base_url.rstrip("/")
        self._session: Optional[aiohttp.ClientSession] = None

    @property
    def platform_name(self) -> str:
        return "SentinelOne"

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                headers={"Authorization": f"APIToken {self.api_token}"}
            )
        return self._session

    async def authenticate(self) -> bool:
        """Verify API token is valid."""
        try:
            session = await self._get_session()

            async with session.get(
                f"{self.base_url}/web/api/v2.1/users/api-token-details"
            ) as resp:
                if resp.status == 200:
                    logger.info("SentinelOne authentication successful")
                    return True
                else:
                    logger.error(f"SentinelOne auth failed: {resp.status}")
                    return False

        except Exception as e:
            logger.error(f"SentinelOne auth error: {e}")
            return False

    async def get_detections(
        self,
        start_time: datetime,
        end_time: Optional[datetime] = None,
        host_id: Optional[str] = None,
    ) -> list[DetectionEvent]:
        """Query SentinelOne threats."""
        end_time = end_time or datetime.now(timezone.utc)
        session = await self._get_session()

        params = {
            "createdAt__gte": start_time.strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
            "createdAt__lte": end_time.strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
            "limit": 100,
        }
        if host_id:
            params["agentIds"] = host_id

        async with session.get(
            f"{self.base_url}/web/api/v2.1/threats",
            params=params,
        ) as resp:
            if resp.status != 200:
                logger.error(f"SentinelOne query failed: {resp.status}")
                return []

            data = await resp.json()
            threats = data.get("data", [])

            return [self._parse_threat(t) for t in threats]

    async def get_detection_details(self, detection_id: str) -> Optional[DetectionEvent]:
        """Get detailed threat information."""
        try:
            session = await self._get_session()

            async with session.get(
                f"{self.base_url}/web/api/v2.1/threats/{detection_id}"
            ) as resp:
                if resp.status != 200:
                    return None

                data = await resp.json()
                threat = data.get("data", {})
                if threat:
                    return self._parse_threat(threat)
                return None

        except Exception as e:
            logger.error(f"Failed to get threat details: {e}")
            return None

    async def get_host_status(self, host_id: str) -> dict:
        """Get agent status from SentinelOne."""
        try:
            session = await self._get_session()

            async with session.get(
                f"{self.base_url}/web/api/v2.1/agents",
                params={"ids": host_id},
            ) as resp:
                if resp.status != 200:
                    return {}

                data = await resp.json()
                agents = data.get("data", [])
                if agents:
                    agent = agents[0]
                    return {
                        "host_id": agent.get("id"),
                        "hostname": agent.get("computerName"),
                        "status": agent.get("networkStatus"),
                        "last_seen": agent.get("lastActiveDate"),
                        "platform": agent.get("osType"),
                        "os_version": agent.get("osName"),
                        "agent_version": agent.get("agentVersion"),
                    }
                return {}

        except Exception as e:
            logger.error(f"Failed to get agent status: {e}")
            return {}

    def _parse_threat(self, data: dict) -> DetectionEvent:
        """Parse SentinelOne threat into standardized format."""
        severity_map = {
            "Low": DetectionSeverity.LOW,
            "Medium": DetectionSeverity.MEDIUM,
            "High": DetectionSeverity.HIGH,
            "Critical": DetectionSeverity.CRITICAL,
        }

        threat_info = data.get("threatInfo", {})
        agent_info = data.get("agentRealtimeInfo", {})

        return DetectionEvent(
            event_id=data.get("id", ""),
            source=self.platform_name,
            timestamp=datetime.fromisoformat(
                data.get("createdAt", datetime.now(timezone.utc).isoformat()).replace("Z", "+00:00")
            ),
            severity=severity_map.get(
                threat_info.get("confidenceLevel", "Low"),
                DetectionSeverity.LOW
            ),
            detection_type=threat_info.get("engines", ["unknown"])[0] if threat_info.get("engines") else "unknown",
            threat_name=threat_info.get("threatName", "Unknown Threat"),
            threat_description=threat_info.get("classification", ""),
            host_name=agent_info.get("agentComputerName"),
            host_id=data.get("agentId"),
            process_name=threat_info.get("originatorProcess"),
            file_path=threat_info.get("filePath"),
            file_hash=threat_info.get("sha256"),
            command_line=threat_info.get("processCommandLine"),
            action_taken=threat_info.get("incidentStatus", ""),
            mitre_tactics=threat_info.get("mitigationReport", {}).get("kill", {}).get("tactics", []),
            raw_data=data,
        )

    async def close(self) -> None:
        """Close HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()


class DefenderClient(EDRClient):
    """
    Microsoft Defender for Endpoint API client.

    Uses Azure AD OAuth2 authentication.
    API documentation: https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/apis-intro
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        base_url: str = "https://api.securitycenter.microsoft.com",
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url
        self._access_token: Optional[str] = None
        self._token_expires: Optional[datetime] = None
        self._session: Optional[aiohttp.ClientSession] = None

    @property
    def platform_name(self) -> str:
        return "Microsoft Defender for Endpoint"

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def authenticate(self) -> bool:
        """Authenticate using Azure AD OAuth2."""
        try:
            session = await self._get_session()

            auth_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"

            async with session.post(
                auth_url,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "https://api.securitycenter.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            ) as resp:
                if resp.status != 200:
                    logger.error(f"Defender auth failed: {resp.status}")
                    return False

                data = await resp.json()
                self._access_token = data["access_token"]
                self._token_expires = datetime.now(timezone.utc) + timedelta(
                    seconds=data["expires_in"] - 60
                )

                logger.info("Defender authentication successful")
                return True

        except Exception as e:
            logger.error(f"Defender auth error: {e}")
            return False

    async def _ensure_authenticated(self) -> None:
        """Ensure we have a valid access token."""
        if (
            not self._access_token or
            not self._token_expires or
            datetime.now(timezone.utc) >= self._token_expires
        ):
            success = await self.authenticate()
            if not success:
                raise RuntimeError("Failed to authenticate with Defender")

    async def _api_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
    ) -> dict:
        """Make authenticated API request."""
        await self._ensure_authenticated()
        session = await self._get_session()

        headers = {"Authorization": f"Bearer {self._access_token}"}

        async with session.request(
            method,
            f"{self.base_url}{endpoint}",
            params=params,
            headers=headers,
        ) as resp:
            if resp.status == 401:
                self._access_token = None
                await self._ensure_authenticated()
                return await self._api_request(method, endpoint, params)

            resp.raise_for_status()
            return await resp.json()

    async def get_detections(
        self,
        start_time: datetime,
        end_time: Optional[datetime] = None,
        host_id: Optional[str] = None,
    ) -> list[DetectionEvent]:
        """Query Defender alerts."""
        end_time = end_time or datetime.now(timezone.utc)

        # Build OData filter
        filter_parts = [
            f"alertCreationTime ge {start_time.strftime('%Y-%m-%dT%H:%M:%SZ')}",
            f"alertCreationTime le {end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        ]
        if host_id:
            filter_parts.append(f"machineId eq '{host_id}'")

        odata_filter = " and ".join(filter_parts)

        response = await self._api_request(
            "GET",
            "/api/alerts",
            params={"$filter": odata_filter, "$top": 100},
        )

        alerts = response.get("value", [])
        return [self._parse_alert(a) for a in alerts]

    async def get_detection_details(self, detection_id: str) -> Optional[DetectionEvent]:
        """Get detailed alert information."""
        try:
            response = await self._api_request(
                "GET",
                f"/api/alerts/{detection_id}",
            )
            return self._parse_alert(response)

        except Exception as e:
            logger.error(f"Failed to get alert details: {e}")
            return None

    async def get_host_status(self, host_id: str) -> dict:
        """Get machine status from Defender."""
        try:
            response = await self._api_request(
                "GET",
                f"/api/machines/{host_id}",
            )

            return {
                "host_id": response.get("id"),
                "hostname": response.get("computerDnsName"),
                "status": response.get("healthStatus"),
                "last_seen": response.get("lastSeen"),
                "platform": response.get("osPlatform"),
                "os_version": response.get("osVersion"),
                "agent_version": response.get("agentVersion"),
            }

        except Exception as e:
            logger.error(f"Failed to get machine status: {e}")
            return {}

    def _parse_alert(self, data: dict) -> DetectionEvent:
        """Parse Defender alert into standardized format."""
        severity_map = {
            "Informational": DetectionSeverity.INFO,
            "Low": DetectionSeverity.LOW,
            "Medium": DetectionSeverity.MEDIUM,
            "High": DetectionSeverity.HIGH,
        }

        return DetectionEvent(
            event_id=data.get("id", ""),
            source=self.platform_name,
            timestamp=datetime.fromisoformat(
                data.get("alertCreationTime", datetime.now(timezone.utc).isoformat()).replace("Z", "+00:00")
            ),
            severity=severity_map.get(
                data.get("severity", "Low"),
                DetectionSeverity.LOW
            ),
            detection_type=data.get("detectionSource", "unknown"),
            threat_name=data.get("title", "Unknown Threat"),
            threat_description=data.get("description", ""),
            host_name=data.get("computerDnsName"),
            host_id=data.get("machineId"),
            process_name=data.get("fileName"),
            file_path=data.get("filePath"),
            file_hash=data.get("sha256"),
            action_taken=data.get("status", ""),
            mitre_tactics=[data.get("category", "")] if data.get("category") else [],
            raw_data=data,
        )

    async def close(self) -> None:
        """Close HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()


class EDRManager:
    """
    Manages multiple EDR integrations for Crucible.

    Coordinates detection queries across all configured EDR platforms
    to provide unified detection visibility.
    """

    def __init__(self):
        self._clients: dict[str, EDRClient] = {}

    def register_client(self, name: str, client: EDRClient) -> None:
        """Register an EDR client."""
        self._clients[name] = client
        logger.info(f"Registered EDR client: {name} ({client.platform_name})")

    async def authenticate_all(self) -> dict[str, bool]:
        """Authenticate all registered clients."""
        results = {}
        for name, client in self._clients.items():
            results[name] = await client.authenticate()
        return results

    async def get_all_detections(
        self,
        start_time: datetime,
        end_time: Optional[datetime] = None,
        host_id: Optional[str] = None,
    ) -> list[DetectionEvent]:
        """Query detections from all EDR platforms."""
        all_detections = []

        tasks = [
            client.get_detections(start_time, end_time, host_id)
            for client in self._clients.values()
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                all_detections.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"EDR query failed: {result}")

        # Sort by timestamp
        all_detections.sort(key=lambda d: d.timestamp, reverse=True)

        return all_detections

    async def close_all(self) -> None:
        """Close all client sessions."""
        for client in self._clients.values():
            await client.close()
