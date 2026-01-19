"""
Mirqab Cloud Relay SDK
Client SDK for Master Server to connect and interact with Cloud Relay infrastructure
"""

from .client import CloudRelayClient
from .models import (
    RelayCredentials,
    C2Channel,
    C2ChannelType,
    BeaconSession,
    PayloadInfo,
    RelayStatus,
)
from .exceptions import (
    RelayError,
    AuthenticationError,
    ConnectionError,
    ProvisioningError,
)

__version__ = "1.0.0"
__all__ = [
    "CloudRelayClient",
    "RelayCredentials",
    "C2Channel",
    "C2ChannelType",
    "BeaconSession",
    "PayloadInfo",
    "RelayStatus",
    "RelayError",
    "AuthenticationError",
    "ConnectionError",
    "ProvisioningError",
]
