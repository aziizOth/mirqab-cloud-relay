"""
Mirqab Crucible - Isolated Malware/Ransomware Execution Environment

Crucible provides a safe, isolated environment for executing malware samples
and validating EDR/AV detection capabilities. All tests run in disposable VMs
with complete network isolation.
"""

from .controller import CrucibleController, VMConfig, VMState, VMInstance
from .agent import CrucibleAgent, ExecutionResult, MalwareSample
from .edr_integration import (
    EDRClient,
    CrowdStrikeClient,
    SentinelOneClient,
    DefenderClient,
    DetectionEvent,
)
from .payload_manager import PayloadManager, EncryptedPayload
from .safety import SafetyController, IsolationStatus

__all__ = [
    # Controller
    "CrucibleController",
    "VMConfig",
    "VMState",
    "VMInstance",
    # Agent
    "CrucibleAgent",
    "ExecutionResult",
    "MalwareSample",
    # EDR Integration
    "EDRClient",
    "CrowdStrikeClient",
    "SentinelOneClient",
    "DefenderClient",
    "DetectionEvent",
    # Payload Management
    "PayloadManager",
    "EncryptedPayload",
    # Safety
    "SafetyController",
    "IsolationStatus",
]

__version__ = "1.0.0"
