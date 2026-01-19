"""
Mirqab Cloud Relay SDK - Main Client
Primary client class for Master Server to interact with Cloud Relay
"""

import hashlib
import json
import logging
import os
import ssl
import tempfile
import threading
import time
from datetime import datetime
from typing import Optional, Callable, BinaryIO
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

from .models import (
    RelayCredentials,
    RelayStatus,
    C2Channel,
    C2ChannelType,
    BeaconSession,
    PayloadInfo,
    TaskCommand,
    ChannelStatus,
)
from .exceptions import (
    RelayError,
    AuthenticationError,
    ConnectionError,
    ProvisioningError,
    ChannelError,
    PayloadError,
    QuotaExceededError,
    TenantSuspendedError,
    TenantExpiredError,
)

logger = logging.getLogger(__name__)


class MTLSAdapter(HTTPAdapter):
    """
    Custom HTTP adapter for mutual TLS authentication.
    Uses client certificate for authentication with Cloud Relay.
    """

    def __init__(
        self,
        client_cert: str,
        client_key: str,
        ca_cert: str,
        **kwargs,
    ):
        self._client_cert = client_cert
        self._client_key = client_key
        self._ca_cert = ca_cert
        self._cert_files = []
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        # Write certs to temp files for SSL context
        cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
        cert_file.write(self._client_cert.encode())
        cert_file.close()
        self._cert_files.append(cert_file.name)

        key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".key")
        key_file.write(self._client_key.encode())
        key_file.close()
        self._cert_files.append(key_file.name)

        ca_file = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
        ca_file.write(self._ca_cert.encode())
        ca_file.close()
        self._cert_files.append(ca_file.name)

        ctx = create_urllib3_context()
        ctx.load_cert_chain(cert_file.name, key_file.name)
        ctx.load_verify_locations(ca_file.name)

        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)

    def close(self):
        super().close()
        # Cleanup temp files
        for f in self._cert_files:
            try:
                os.unlink(f)
            except OSError:
                pass


class CloudRelayClient:
    """
    Main client for interacting with Mirqab Cloud Relay.

    Usage:
        # Initialize with credentials from Command Center
        credentials = RelayCredentials.from_file("relay_credentials.json")
        client = CloudRelayClient(credentials)

        # Check relay status
        status = client.get_status()
        print(f"Relay status: {status.status}")

        # List active C2 channels
        channels = client.list_channels()
        for channel in channels:
            print(f"Channel: {channel.name} ({channel.channel_type.value})")

        # Get beacon sessions
        sessions = client.list_sessions()
        for session in sessions:
            print(f"Session: {session.hostname} - {session.status.value}")

        # Upload payload
        payload = client.upload_payload(
            file_path="/path/to/payload.exe",
            filename="legit.exe",
            expires_hours=24,
        )
        print(f"Payload URL: {payload.download_url}")

        # Start heartbeat
        client.start_heartbeat()

        # Cleanup
        client.close()
    """

    def __init__(
        self,
        credentials: RelayCredentials,
        timeout: int = 30,
        verify_ssl: bool = True,
    ):
        """
        Initialize the Cloud Relay client.

        Args:
            credentials: RelayCredentials from Command Center
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.credentials = credentials
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        self._session: Optional[requests.Session] = None
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._heartbeat_running = False
        self._last_heartbeat: Optional[datetime] = None
        self._status_callbacks: list[Callable[[RelayStatus], None]] = []

        # Initialize session
        self._init_session()

    def _init_session(self) -> None:
        """Initialize the requests session with mTLS."""
        self._session = requests.Session()

        # Set up mTLS adapter
        adapter = MTLSAdapter(
            client_cert=self.credentials.client_certificate,
            client_key=self.credentials.client_key,
            ca_cert=self.credentials.ca_certificate,
        )
        self._session.mount("https://", adapter)

        # Set default headers
        self._session.headers.update({
            "Authorization": f"Bearer {self.credentials.api_token}",
            "X-Tenant-ID": self.credentials.tenant_id,
            "Content-Type": "application/json",
            "User-Agent": "MirqabRelaySDK/1.0",
        })

    def _request(
        self,
        method: str,
        endpoint: str,
        base_url: Optional[str] = None,
        **kwargs,
    ) -> dict:
        """
        Make an authenticated request to Cloud Relay.

        Args:
            method: HTTP method
            endpoint: API endpoint (relative path)
            base_url: Base URL override
            **kwargs: Additional request arguments

        Returns:
            Response JSON as dictionary

        Raises:
            RelayError: On API errors
        """
        if self.credentials.is_expired:
            raise TenantExpiredError("Credentials have expired")

        base = base_url or self.credentials.relay_endpoint
        url = urljoin(base, endpoint)

        try:
            response = self._session.request(
                method,
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs,
            )

            # Handle error responses
            if response.status_code == 401:
                raise AuthenticationError("Authentication failed")
            elif response.status_code == 403:
                error_data = response.json() if response.text else {}
                error_code = error_data.get("error_code", "")
                if "SUSPENDED" in error_code:
                    raise TenantSuspendedError("Tenant is suspended")
                elif "EXPIRED" in error_code:
                    raise TenantExpiredError("Tenant subscription expired")
                elif "QUOTA" in error_code:
                    raise QuotaExceededError("Quota exceeded")
                raise AuthenticationError(f"Access denied: {error_data.get('message', '')}")
            elif response.status_code >= 400:
                error_data = response.json() if response.text else {}
                raise RelayError(
                    error_data.get("message", f"Request failed: {response.status_code}"),
                    error_data.get("error_code"),
                )

            return response.json() if response.text else {}

        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"Connection failed: {e}")
        except requests.exceptions.Timeout as e:
            raise ConnectionError(f"Request timed out: {e}")
        except requests.exceptions.RequestException as e:
            raise RelayError(f"Request error: {e}")

    # =========================================================================
    # Status & Health
    # =========================================================================

    def get_status(self) -> RelayStatus:
        """
        Get the overall status of the Cloud Relay tenant.

        Returns:
            RelayStatus with service health information
        """
        data = self._request("GET", "/api/v1/status")
        return RelayStatus.from_dict(data)

    def health_check(self) -> bool:
        """
        Quick health check of relay connectivity.

        Returns:
            True if relay is reachable and authenticated
        """
        try:
            self._request("GET", "/health")
            return True
        except RelayError:
            return False

    # =========================================================================
    # C2 Channel Management
    # =========================================================================

    def list_channels(self) -> list[C2Channel]:
        """
        List all C2 channels for this tenant.

        Returns:
            List of C2Channel objects
        """
        data = self._request("GET", "/api/v1/channels")
        return [C2Channel.from_dict(c) for c in data.get("channels", [])]

    def get_channel(self, channel_id: str) -> C2Channel:
        """
        Get details of a specific C2 channel.

        Args:
            channel_id: The channel ID

        Returns:
            C2Channel object
        """
        data = self._request("GET", f"/api/v1/channels/{channel_id}")
        return C2Channel.from_dict(data)

    def create_channel(
        self,
        name: str,
        channel_type: C2ChannelType,
        config: Optional[dict] = None,
    ) -> C2Channel:
        """
        Create a new C2 channel.

        Args:
            name: Display name for the channel
            channel_type: Type of C2 channel (HTTP, DNS, etc.)
            config: Channel-specific configuration

        Returns:
            Created C2Channel object
        """
        payload = {
            "name": name,
            "channel_type": channel_type.value,
            "config": config or {},
        }
        data = self._request("POST", "/api/v1/channels", json=payload)
        return C2Channel.from_dict(data)

    def update_channel(
        self,
        channel_id: str,
        name: Optional[str] = None,
        config: Optional[dict] = None,
    ) -> C2Channel:
        """
        Update an existing C2 channel.

        Args:
            channel_id: The channel ID
            name: New display name
            config: New configuration

        Returns:
            Updated C2Channel object
        """
        payload = {}
        if name:
            payload["name"] = name
        if config:
            payload["config"] = config

        data = self._request("PATCH", f"/api/v1/channels/{channel_id}", json=payload)
        return C2Channel.from_dict(data)

    def delete_channel(self, channel_id: str) -> bool:
        """
        Delete a C2 channel and all associated sessions.

        Args:
            channel_id: The channel ID

        Returns:
            True if successful
        """
        self._request("DELETE", f"/api/v1/channels/{channel_id}")
        return True

    def pause_channel(self, channel_id: str) -> C2Channel:
        """Pause a C2 channel (stops accepting new connections)."""
        data = self._request("POST", f"/api/v1/channels/{channel_id}/pause")
        return C2Channel.from_dict(data)

    def resume_channel(self, channel_id: str) -> C2Channel:
        """Resume a paused C2 channel."""
        data = self._request("POST", f"/api/v1/channels/{channel_id}/resume")
        return C2Channel.from_dict(data)

    # =========================================================================
    # Session Management
    # =========================================================================

    def list_sessions(
        self,
        channel_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[BeaconSession]:
        """
        List beacon sessions.

        Args:
            channel_id: Filter by channel
            status: Filter by status (active, dormant, lost)

        Returns:
            List of BeaconSession objects
        """
        params = {}
        if channel_id:
            params["channel_id"] = channel_id
        if status:
            params["status"] = status

        data = self._request("GET", "/api/v1/sessions", params=params)
        return [BeaconSession.from_dict(s) for s in data.get("sessions", [])]

    def get_session(self, session_id: str) -> BeaconSession:
        """
        Get details of a specific beacon session.

        Args:
            session_id: The session ID

        Returns:
            BeaconSession object
        """
        data = self._request("GET", f"/api/v1/sessions/{session_id}")
        return BeaconSession.from_dict(data)

    def terminate_session(self, session_id: str) -> bool:
        """
        Terminate a beacon session.

        Args:
            session_id: The session ID

        Returns:
            True if successful
        """
        self._request("DELETE", f"/api/v1/sessions/{session_id}")
        return True

    def send_command(
        self,
        session_id: str,
        command_type: str,
        payload: dict,
    ) -> TaskCommand:
        """
        Send a command to a beacon session.

        Args:
            session_id: Target session ID
            command_type: Type of command (shell, download, upload, etc.)
            payload: Command payload

        Returns:
            TaskCommand object
        """
        data = self._request(
            "POST",
            f"/api/v1/sessions/{session_id}/commands",
            json={
                "command_type": command_type,
                "payload": payload,
            },
        )
        return TaskCommand.from_dict(data)

    def get_command_result(
        self,
        session_id: str,
        command_id: str,
    ) -> TaskCommand:
        """
        Get the result of a previously sent command.

        Args:
            session_id: Session ID
            command_id: Command ID

        Returns:
            TaskCommand with result
        """
        data = self._request(
            "GET",
            f"/api/v1/sessions/{session_id}/commands/{command_id}",
        )
        return TaskCommand.from_dict(data)

    # =========================================================================
    # Payload Management
    # =========================================================================

    def upload_payload(
        self,
        file_path: Optional[str] = None,
        file_data: Optional[BinaryIO] = None,
        filename: str = "payload",
        content_type: str = "application/octet-stream",
        expires_hours: Optional[int] = None,
        max_downloads: Optional[int] = None,
        metadata: Optional[dict] = None,
    ) -> PayloadInfo:
        """
        Upload a payload to Cloud Relay.

        Args:
            file_path: Path to file to upload
            file_data: File-like object to upload
            filename: Filename for the payload
            content_type: MIME type
            expires_hours: Hours until payload expires
            max_downloads: Maximum download count
            metadata: Custom metadata

        Returns:
            PayloadInfo with download URL
        """
        if file_path:
            with open(file_path, "rb") as f:
                content = f.read()
        elif file_data:
            content = file_data.read()
        else:
            raise PayloadError("Either file_path or file_data is required")

        # Calculate hash
        sha256_hash = hashlib.sha256(content).hexdigest()

        # Upload multipart
        files = {
            "file": (filename, content, content_type),
        }
        data = {
            "filename": filename,
            "sha256_hash": sha256_hash,
        }
        if expires_hours:
            data["expires_hours"] = expires_hours
        if max_downloads:
            data["max_downloads"] = max_downloads
        if metadata:
            data["metadata"] = json.dumps(metadata)

        # Use different content type for multipart
        headers = {"Content-Type": None}  # Let requests set it
        response = self._request(
            "POST",
            "/api/v1/payloads",
            files=files,
            data=data,
            headers=headers,
        )
        return PayloadInfo.from_dict(response)

    def list_payloads(self) -> list[PayloadInfo]:
        """
        List all hosted payloads.

        Returns:
            List of PayloadInfo objects
        """
        data = self._request("GET", "/api/v1/payloads")
        return [PayloadInfo.from_dict(p) for p in data.get("payloads", [])]

    def get_payload(self, payload_id: str) -> PayloadInfo:
        """
        Get details of a specific payload.

        Args:
            payload_id: The payload ID

        Returns:
            PayloadInfo object
        """
        data = self._request("GET", f"/api/v1/payloads/{payload_id}")
        return PayloadInfo.from_dict(data)

    def delete_payload(self, payload_id: str) -> bool:
        """
        Delete a hosted payload.

        Args:
            payload_id: The payload ID

        Returns:
            True if successful
        """
        self._request("DELETE", f"/api/v1/payloads/{payload_id}")
        return True

    # =========================================================================
    # Heartbeat Management
    # =========================================================================

    def send_heartbeat(
        self,
        active_operations: int = 0,
        system_health: Optional[dict] = None,
    ) -> dict:
        """
        Send a heartbeat to Cloud Relay.

        Args:
            active_operations: Number of active operations
            system_health: System health metrics

        Returns:
            Heartbeat response with relay status
        """
        payload = {
            "tenant_id": self.credentials.tenant_id,
            "api_token": self.credentials.api_token,
            "master_server_version": "1.0.0",
            "active_operations": active_operations,
            "system_health": system_health or {},
        }

        data = self._request("POST", "/api/v1/heartbeat", json=payload)
        self._last_heartbeat = datetime.utcnow()
        return data

    def start_heartbeat(
        self,
        interval: int = 60,
        callback: Optional[Callable[[RelayStatus], None]] = None,
    ) -> None:
        """
        Start automatic heartbeat in background thread.

        Args:
            interval: Heartbeat interval in seconds
            callback: Optional callback for status updates
        """
        if self._heartbeat_running:
            return

        if callback:
            self._status_callbacks.append(callback)

        self._heartbeat_running = True
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            args=(interval,),
            daemon=True,
        )
        self._heartbeat_thread.start()
        logger.info(f"Heartbeat started with {interval}s interval")

    def stop_heartbeat(self) -> None:
        """Stop the automatic heartbeat."""
        self._heartbeat_running = False
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5)
            self._heartbeat_thread = None
        logger.info("Heartbeat stopped")

    def _heartbeat_loop(self, interval: int) -> None:
        """Background heartbeat loop."""
        while self._heartbeat_running:
            try:
                response = self.send_heartbeat()
                if self._status_callbacks:
                    status = RelayStatus.from_dict(response.get("relay_status", {}))
                    for callback in self._status_callbacks:
                        try:
                            callback(status)
                        except Exception as e:
                            logger.warning(f"Heartbeat callback error: {e}")
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")

            time.sleep(interval)

    # =========================================================================
    # Cleanup
    # =========================================================================

    def close(self) -> None:
        """Close the client and cleanup resources."""
        self.stop_heartbeat()
        if self._session:
            self._session.close()
            self._session = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
