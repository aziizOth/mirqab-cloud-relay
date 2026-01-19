# Mirqab Cloud Relay - Firewall Management Module
"""
Dynamic firewall management for Network Actor agents.

Features:
- Source-restricted port opening
- Rule lifecycle management
- iptables/nftables support
- Rule persistence and recovery
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class FirewallBackend(str, Enum):
    """Supported firewall backends."""
    IPTABLES = "iptables"
    NFTABLES = "nftables"
    FIREWALLD = "firewalld"
    UFW = "ufw"


@dataclass
class FirewallRule:
    """Firewall rule definition."""
    rule_id: str
    port: int
    source_ip: str
    protocol: str = "tcp"
    action: str = "ACCEPT"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    comment: Optional[str] = None


class FirewallBackendBase(ABC):
    """Base class for firewall backends."""

    @abstractmethod
    async def add_rule(self, rule: FirewallRule) -> bool:
        """Add a firewall rule."""
        pass

    @abstractmethod
    async def remove_rule(self, rule_id: str) -> bool:
        """Remove a firewall rule."""
        pass

    @abstractmethod
    async def list_rules(self) -> list[FirewallRule]:
        """List all managed rules."""
        pass

    @abstractmethod
    async def check_rule_exists(self, rule_id: str) -> bool:
        """Check if a rule exists."""
        pass


class IptablesBackend(FirewallBackendBase):
    """iptables-based firewall management."""

    def __init__(self, chain: str = "INPUT"):
        self.chain = chain
        self._rules: dict[str, FirewallRule] = {}

    async def _run_iptables(self, args: str) -> tuple[int, str, str]:
        """Run iptables command."""
        cmd = f"iptables {args}"
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode, stdout.decode(), stderr.decode()

    async def add_rule(self, rule: FirewallRule) -> bool:
        """Add iptables rule with source IP restriction."""
        # Build iptables command
        # Format: iptables -I INPUT -s SOURCE_IP -p tcp --dport PORT -j ACCEPT -m comment --comment "RULE_ID"
        comment = f"mirqab-na-{rule.rule_id}"
        cmd = (
            f"-I {self.chain} "
            f"-s {rule.source_ip} "
            f"-p {rule.protocol} "
            f"--dport {rule.port} "
            f"-j {rule.action} "
            f"-m comment --comment \"{comment}\""
        )

        returncode, stdout, stderr = await self._run_iptables(cmd)
        if returncode != 0:
            logger.error(f"Failed to add iptables rule: {stderr}")
            return False

        self._rules[rule.rule_id] = rule
        logger.info(f"Added iptables rule: {rule.source_ip}:{rule.port}/{rule.protocol}")
        return True

    async def remove_rule(self, rule_id: str) -> bool:
        """Remove iptables rule by ID."""
        if rule_id not in self._rules:
            logger.warning(f"Rule not found: {rule_id}")
            return False

        rule = self._rules[rule_id]
        comment = f"mirqab-na-{rule_id}"

        # Use -D to delete the matching rule
        cmd = (
            f"-D {self.chain} "
            f"-s {rule.source_ip} "
            f"-p {rule.protocol} "
            f"--dport {rule.port} "
            f"-j {rule.action} "
            f"-m comment --comment \"{comment}\""
        )

        returncode, stdout, stderr = await self._run_iptables(cmd)
        if returncode != 0:
            logger.error(f"Failed to remove iptables rule: {stderr}")
            return False

        del self._rules[rule_id]
        logger.info(f"Removed iptables rule: {rule_id}")
        return True

    async def list_rules(self) -> list[FirewallRule]:
        """List all managed rules."""
        return list(self._rules.values())

    async def check_rule_exists(self, rule_id: str) -> bool:
        """Check if rule exists by searching iptables output."""
        comment = f"mirqab-na-{rule_id}"
        returncode, stdout, _ = await self._run_iptables(f"-L {self.chain} -n --line-numbers")
        return comment in stdout


class NftablesBackend(FirewallBackendBase):
    """nftables-based firewall management."""

    def __init__(self, table: str = "filter", chain: str = "input"):
        self.table = table
        self.chain = chain
        self._rules: dict[str, FirewallRule] = {}

    async def _run_nft(self, args: str) -> tuple[int, str, str]:
        """Run nft command."""
        cmd = f"nft {args}"
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode, stdout.decode(), stderr.decode()

    async def add_rule(self, rule: FirewallRule) -> bool:
        """Add nftables rule with source IP restriction."""
        # Format: nft add rule ip filter input ip saddr SOURCE tcp dport PORT accept comment "RULE_ID"
        comment = f"mirqab-na-{rule.rule_id}"
        cmd = (
            f"add rule ip {self.table} {self.chain} "
            f"ip saddr {rule.source_ip} "
            f"{rule.protocol} dport {rule.port} "
            f"accept "
            f'comment "{comment}"'
        )

        returncode, stdout, stderr = await self._run_nft(cmd)
        if returncode != 0:
            logger.error(f"Failed to add nftables rule: {stderr}")
            return False

        self._rules[rule.rule_id] = rule
        logger.info(f"Added nftables rule: {rule.source_ip}:{rule.port}/{rule.protocol}")
        return True

    async def remove_rule(self, rule_id: str) -> bool:
        """Remove nftables rule by handle."""
        if rule_id not in self._rules:
            logger.warning(f"Rule not found: {rule_id}")
            return False

        # Find rule handle by comment
        comment = f"mirqab-na-{rule_id}"
        returncode, stdout, _ = await self._run_nft(f"-a list chain ip {self.table} {self.chain}")

        if returncode != 0:
            return False

        # Parse output to find handle
        handle = None
        for line in stdout.split("\n"):
            if comment in line and "handle" in line:
                parts = line.split("handle")
                if len(parts) > 1:
                    handle = parts[1].strip().split()[0]
                    break

        if handle:
            returncode, _, stderr = await self._run_nft(
                f"delete rule ip {self.table} {self.chain} handle {handle}"
            )
            if returncode != 0:
                logger.error(f"Failed to remove nftables rule: {stderr}")
                return False

        del self._rules[rule_id]
        logger.info(f"Removed nftables rule: {rule_id}")
        return True

    async def list_rules(self) -> list[FirewallRule]:
        """List all managed rules."""
        return list(self._rules.values())

    async def check_rule_exists(self, rule_id: str) -> bool:
        """Check if rule exists."""
        return rule_id in self._rules


class UfwBackend(FirewallBackendBase):
    """UFW-based firewall management (Ubuntu Firewall)."""

    def __init__(self):
        self._rules: dict[str, FirewallRule] = {}

    async def _run_ufw(self, args: str) -> tuple[int, str, str]:
        """Run ufw command."""
        cmd = f"ufw {args}"
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode, stdout.decode(), stderr.decode()

    async def add_rule(self, rule: FirewallRule) -> bool:
        """Add UFW rule with source IP restriction."""
        # Format: ufw allow from SOURCE to any port PORT proto PROTO comment "RULE_ID"
        comment = f"mirqab-na-{rule.rule_id}"
        cmd = (
            f"allow from {rule.source_ip} to any port {rule.port} "
            f"proto {rule.protocol} comment '{comment}'"
        )

        returncode, stdout, stderr = await self._run_ufw(cmd)
        if returncode != 0:
            logger.error(f"Failed to add UFW rule: {stderr}")
            return False

        self._rules[rule.rule_id] = rule
        logger.info(f"Added UFW rule: {rule.source_ip}:{rule.port}/{rule.protocol}")
        return True

    async def remove_rule(self, rule_id: str) -> bool:
        """Remove UFW rule."""
        if rule_id not in self._rules:
            logger.warning(f"Rule not found: {rule_id}")
            return False

        rule = self._rules[rule_id]
        cmd = (
            f"delete allow from {rule.source_ip} to any port {rule.port} "
            f"proto {rule.protocol}"
        )

        returncode, stdout, stderr = await self._run_ufw(cmd)
        if returncode != 0:
            logger.error(f"Failed to remove UFW rule: {stderr}")
            return False

        del self._rules[rule_id]
        logger.info(f"Removed UFW rule: {rule_id}")
        return True

    async def list_rules(self) -> list[FirewallRule]:
        """List all managed rules."""
        return list(self._rules.values())

    async def check_rule_exists(self, rule_id: str) -> bool:
        """Check if rule exists."""
        return rule_id in self._rules


class FirewallManager:
    """
    High-level firewall manager.

    Auto-detects available firewall backend and provides
    unified interface for rule management.
    """

    def __init__(self, backend: Optional[FirewallBackend] = None):
        self.backend_type = backend
        self._backend: Optional[FirewallBackendBase] = None
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize firewall backend."""
        if self._initialized:
            return

        # Auto-detect backend if not specified
        if self.backend_type is None:
            self.backend_type = await self._detect_backend()

        # Create backend instance
        if self.backend_type == FirewallBackend.IPTABLES:
            self._backend = IptablesBackend()
        elif self.backend_type == FirewallBackend.NFTABLES:
            self._backend = NftablesBackend()
        elif self.backend_type == FirewallBackend.UFW:
            self._backend = UfwBackend()
        else:
            raise ValueError(f"Unsupported firewall backend: {self.backend_type}")

        self._initialized = True
        logger.info(f"Firewall manager initialized with {self.backend_type.value}")

    async def _detect_backend(self) -> FirewallBackend:
        """Auto-detect available firewall backend."""
        # Check for UFW first (common on Ubuntu)
        proc = await asyncio.create_subprocess_shell(
            "which ufw && ufw status",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        returncode, _, _ = await proc.communicate()
        if returncode == 0:
            return FirewallBackend.UFW

        # Check for nftables
        proc = await asyncio.create_subprocess_shell(
            "which nft && nft list tables",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        returncode, _, _ = await proc.communicate()
        if returncode == 0:
            return FirewallBackend.NFTABLES

        # Default to iptables
        return FirewallBackend.IPTABLES

    async def add_rule(
        self,
        rule_id: str,
        port: int,
        source_ip: str,
        protocol: str = "tcp",
    ) -> bool:
        """Add a source-restricted firewall rule."""
        if not self._initialized:
            await self.initialize()

        rule = FirewallRule(
            rule_id=rule_id,
            port=port,
            source_ip=source_ip,
            protocol=protocol,
            comment=f"Mirqab Network Actor: {rule_id}",
        )

        return await self._backend.add_rule(rule)

    async def remove_rule(self, rule_id: str) -> bool:
        """Remove a firewall rule."""
        if not self._initialized:
            await self.initialize()

        return await self._backend.remove_rule(rule_id)

    async def list_rules(self) -> list[FirewallRule]:
        """List all managed rules."""
        if not self._initialized:
            await self.initialize()

        return await self._backend.list_rules()

    async def cleanup_all_rules(self) -> int:
        """Remove all managed rules. Returns count of removed rules."""
        if not self._initialized:
            await self.initialize()

        rules = await self.list_rules()
        removed = 0
        for rule in rules:
            if await self.remove_rule(rule.rule_id):
                removed += 1

        logger.info(f"Cleaned up {removed} firewall rules")
        return removed
