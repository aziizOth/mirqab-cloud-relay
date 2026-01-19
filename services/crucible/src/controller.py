"""
Crucible Controller - VM Lifecycle and Snapshot Management

Manages isolated VMs for safe malware execution testing. Provides:
- VM lifecycle management (create, start, stop, destroy)
- Snapshot management (create baseline, restore after tests)
- Isolation verification (network isolation checks)
- Hypervisor abstraction (libvirt, VirtualBox, VMware)
"""

import asyncio
import logging
import subprocess
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class VMState(Enum):
    """VM lifecycle states."""

    UNKNOWN = "unknown"
    CREATING = "creating"
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    SNAPSHOTTING = "snapshotting"
    RESTORING = "restoring"
    DESTROYING = "destroying"
    DESTROYED = "destroyed"
    ERROR = "error"


class HypervisorType(Enum):
    """Supported hypervisor backends."""

    LIBVIRT = "libvirt"
    VIRTUALBOX = "virtualbox"
    VMWARE = "vmware"


@dataclass
class VMConfig:
    """Configuration for a Crucible VM instance."""

    name: str
    base_image: str  # Path to golden image OVA
    memory_mb: int = 4096
    vcpus: int = 2
    disk_gb: int = 40

    # Network isolation settings
    isolated_network: bool = True
    network_name: str = "crucible-isolated"

    # Snapshot settings
    baseline_snapshot: str = "crucible-baseline"
    auto_restore: bool = True

    # Timeouts
    start_timeout_seconds: int = 120
    stop_timeout_seconds: int = 60
    snapshot_timeout_seconds: int = 300

    # Agent communication
    agent_port: int = 9443
    agent_api_key: Optional[str] = None


@dataclass
class VMInstance:
    """Represents a running Crucible VM instance."""

    instance_id: str
    config: VMConfig
    state: VMState = VMState.UNKNOWN
    hypervisor_id: Optional[str] = None  # Hypervisor-specific VM ID
    ip_address: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_state_change: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    current_snapshot: Optional[str] = None
    error_message: Optional[str] = None

    def update_state(self, new_state: VMState, error: Optional[str] = None) -> None:
        """Update VM state with timestamp."""
        self.state = new_state
        self.last_state_change = datetime.now(timezone.utc)
        if error:
            self.error_message = error
        logger.info(
            f"VM {self.instance_id} state changed to {new_state.value}",
            extra={"vm_id": self.instance_id, "state": new_state.value},
        )


class HypervisorBackend(ABC):
    """Abstract base class for hypervisor backends."""

    @abstractmethod
    async def create_vm(self, config: VMConfig) -> str:
        """Create a new VM from the golden image. Returns hypervisor VM ID."""
        pass

    @abstractmethod
    async def start_vm(self, vm_id: str) -> None:
        """Start a stopped VM."""
        pass

    @abstractmethod
    async def stop_vm(self, vm_id: str, force: bool = False) -> None:
        """Stop a running VM."""
        pass

    @abstractmethod
    async def destroy_vm(self, vm_id: str) -> None:
        """Destroy a VM and clean up resources."""
        pass

    @abstractmethod
    async def get_vm_state(self, vm_id: str) -> VMState:
        """Get current VM state."""
        pass

    @abstractmethod
    async def get_vm_ip(self, vm_id: str) -> Optional[str]:
        """Get VM IP address."""
        pass

    @abstractmethod
    async def create_snapshot(self, vm_id: str, snapshot_name: str) -> None:
        """Create a VM snapshot."""
        pass

    @abstractmethod
    async def restore_snapshot(self, vm_id: str, snapshot_name: str) -> None:
        """Restore VM to a snapshot."""
        pass

    @abstractmethod
    async def delete_snapshot(self, vm_id: str, snapshot_name: str) -> None:
        """Delete a VM snapshot."""
        pass

    @abstractmethod
    async def verify_isolation(self, vm_id: str) -> bool:
        """Verify VM network isolation."""
        pass


class LibvirtBackend(HypervisorBackend):
    """Libvirt/KVM hypervisor backend."""

    def __init__(self, connection_uri: str = "qemu:///system"):
        self.connection_uri = connection_uri
        self._conn = None

    async def _get_connection(self):
        """Lazy connection to libvirt."""
        if self._conn is None:
            try:
                import libvirt
                self._conn = libvirt.open(self.connection_uri)
            except ImportError:
                raise RuntimeError("libvirt-python not installed")
            except libvirt.libvirtError as e:
                raise RuntimeError(f"Failed to connect to libvirt: {e}")
        return self._conn

    async def create_vm(self, config: VMConfig) -> str:
        """Create VM from OVA using virt-install."""
        vm_name = f"crucible-{config.name}-{uuid.uuid4().hex[:8]}"

        # Convert OVA to qcow2 if needed
        base_image = Path(config.base_image)
        if base_image.suffix.lower() == ".ova":
            qcow2_path = await self._convert_ova_to_qcow2(base_image, vm_name)
        else:
            qcow2_path = str(base_image)

        # Create VM with virt-install
        cmd = [
            "virt-install",
            "--name", vm_name,
            "--memory", str(config.memory_mb),
            "--vcpus", str(config.vcpus),
            "--disk", f"path={qcow2_path},format=qcow2",
            "--import",
            "--os-variant", "win10",  # Adjust based on golden image
            "--noautoconsole",
        ]

        if config.isolated_network:
            cmd.extend(["--network", f"network={config.network_name}"])
        else:
            cmd.extend(["--network", "bridge=virbr0"])

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            raise RuntimeError(f"virt-install failed: {stderr.decode()}")

        logger.info(f"Created VM {vm_name}")
        return vm_name

    async def _convert_ova_to_qcow2(self, ova_path: Path, vm_name: str) -> str:
        """Extract and convert OVA to qcow2 format."""
        import tarfile
        import tempfile

        work_dir = Path(tempfile.mkdtemp(prefix="crucible-"))
        qcow2_path = f"/var/lib/libvirt/images/{vm_name}.qcow2"

        # Extract OVA (it's a tar archive)
        with tarfile.open(ova_path) as tar:
            tar.extractall(work_dir)

        # Find the VMDK file
        vmdk_files = list(work_dir.glob("*.vmdk"))
        if not vmdk_files:
            raise RuntimeError(f"No VMDK found in OVA: {ova_path}")

        vmdk_path = vmdk_files[0]

        # Convert VMDK to qcow2
        cmd = [
            "qemu-img", "convert",
            "-f", "vmdk",
            "-O", "qcow2",
            str(vmdk_path),
            qcow2_path,
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        if process.returncode != 0:
            raise RuntimeError(f"qemu-img convert failed: {stderr.decode()}")

        # Cleanup temp directory
        import shutil
        shutil.rmtree(work_dir)

        return qcow2_path

    async def start_vm(self, vm_id: str) -> None:
        """Start VM using virsh."""
        await self._run_virsh("start", vm_id)

    async def stop_vm(self, vm_id: str, force: bool = False) -> None:
        """Stop VM using virsh."""
        action = "destroy" if force else "shutdown"
        await self._run_virsh(action, vm_id)

    async def destroy_vm(self, vm_id: str) -> None:
        """Destroy VM and remove disk."""
        # Stop if running
        try:
            await self._run_virsh("destroy", vm_id)
        except RuntimeError:
            pass  # VM might already be stopped

        # Undefine (removes VM config)
        await self._run_virsh("undefine", vm_id, "--remove-all-storage")

    async def get_vm_state(self, vm_id: str) -> VMState:
        """Get VM state from virsh."""
        try:
            result = await self._run_virsh("domstate", vm_id)
            state_str = result.strip().lower()

            state_map = {
                "running": VMState.RUNNING,
                "shut off": VMState.STOPPED,
                "paused": VMState.STOPPED,
                "in shutdown": VMState.STOPPING,
                "crashed": VMState.ERROR,
            }
            return state_map.get(state_str, VMState.UNKNOWN)
        except RuntimeError:
            return VMState.UNKNOWN

    async def get_vm_ip(self, vm_id: str) -> Optional[str]:
        """Get VM IP address from DHCP leases."""
        try:
            result = await self._run_virsh("domifaddr", vm_id)
            # Parse output for IP address
            for line in result.split("\n"):
                if "ipv4" in line.lower():
                    parts = line.split()
                    for part in parts:
                        if "/" in part:  # IP/prefix format
                            return part.split("/")[0]
            return None
        except RuntimeError:
            return None

    async def create_snapshot(self, vm_id: str, snapshot_name: str) -> None:
        """Create VM snapshot."""
        await self._run_virsh(
            "snapshot-create-as",
            vm_id,
            "--name", snapshot_name,
            "--description", f"Crucible snapshot at {datetime.now(timezone.utc).isoformat()}",
            "--atomic",
        )

    async def restore_snapshot(self, vm_id: str, snapshot_name: str) -> None:
        """Restore VM to snapshot."""
        await self._run_virsh("snapshot-revert", vm_id, snapshot_name)

    async def delete_snapshot(self, vm_id: str, snapshot_name: str) -> None:
        """Delete VM snapshot."""
        await self._run_virsh("snapshot-delete", vm_id, snapshot_name)

    async def verify_isolation(self, vm_id: str) -> bool:
        """Verify VM is on isolated network."""
        try:
            result = await self._run_virsh("domiflist", vm_id)
            return "crucible-isolated" in result
        except RuntimeError:
            return False

    async def _run_virsh(self, *args: str) -> str:
        """Run virsh command."""
        cmd = ["virsh", "-c", self.connection_uri] + list(args)

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            raise RuntimeError(f"virsh {args[0]} failed: {stderr.decode()}")

        return stdout.decode()


class VirtualBoxBackend(HypervisorBackend):
    """VirtualBox hypervisor backend."""

    def __init__(self, vboxmanage_path: str = "VBoxManage"):
        self.vboxmanage = vboxmanage_path

    async def create_vm(self, config: VMConfig) -> str:
        """Import OVA and create VM."""
        vm_name = f"crucible-{config.name}-{uuid.uuid4().hex[:8]}"

        # Import OVA
        cmd = [
            self.vboxmanage, "import", config.base_image,
            "--vsys", "0",
            "--vmname", vm_name,
            "--memory", str(config.memory_mb),
            "--cpus", str(config.vcpus),
        ]

        await self._run_vboxmanage(*cmd)

        # Configure network isolation
        if config.isolated_network:
            await self._run_vboxmanage(
                "modifyvm", vm_name,
                "--nic1", "intnet",
                "--intnet1", config.network_name,
            )

        logger.info(f"Created VirtualBox VM {vm_name}")
        return vm_name

    async def start_vm(self, vm_id: str) -> None:
        """Start VM headless."""
        await self._run_vboxmanage("startvm", vm_id, "--type", "headless")

    async def stop_vm(self, vm_id: str, force: bool = False) -> None:
        """Stop VM."""
        action = "poweroff" if force else "acpipowerbutton"
        await self._run_vboxmanage("controlvm", vm_id, action)

    async def destroy_vm(self, vm_id: str) -> None:
        """Unregister and delete VM."""
        await self._run_vboxmanage("unregistervm", vm_id, "--delete")

    async def get_vm_state(self, vm_id: str) -> VMState:
        """Get VM state."""
        try:
            result = await self._run_vboxmanage("showvminfo", vm_id, "--machinereadable")
            for line in result.split("\n"):
                if line.startswith("VMState="):
                    state_str = line.split("=")[1].strip('"').lower()
                    state_map = {
                        "running": VMState.RUNNING,
                        "poweroff": VMState.STOPPED,
                        "saved": VMState.STOPPED,
                        "aborted": VMState.ERROR,
                    }
                    return state_map.get(state_str, VMState.UNKNOWN)
            return VMState.UNKNOWN
        except RuntimeError:
            return VMState.UNKNOWN

    async def get_vm_ip(self, vm_id: str) -> Optional[str]:
        """Get VM IP address via guest additions."""
        try:
            result = await self._run_vboxmanage(
                "guestproperty", "get", vm_id,
                "/VirtualBox/GuestInfo/Net/0/V4/IP"
            )
            if "Value:" in result:
                return result.split("Value:")[1].strip()
            return None
        except RuntimeError:
            return None

    async def create_snapshot(self, vm_id: str, snapshot_name: str) -> None:
        """Create VM snapshot."""
        await self._run_vboxmanage("snapshot", vm_id, "take", snapshot_name)

    async def restore_snapshot(self, vm_id: str, snapshot_name: str) -> None:
        """Restore VM snapshot."""
        await self._run_vboxmanage("snapshot", vm_id, "restore", snapshot_name)

    async def delete_snapshot(self, vm_id: str, snapshot_name: str) -> None:
        """Delete VM snapshot."""
        await self._run_vboxmanage("snapshot", vm_id, "delete", snapshot_name)

    async def verify_isolation(self, vm_id: str) -> bool:
        """Verify VM network isolation."""
        try:
            result = await self._run_vboxmanage("showvminfo", vm_id, "--machinereadable")
            for line in result.split("\n"):
                if line.startswith("nic1=") and "intnet" in line.lower():
                    return True
            return False
        except RuntimeError:
            return False

    async def _run_vboxmanage(self, *args: str) -> str:
        """Run VBoxManage command."""
        cmd = [self.vboxmanage] + list(args)

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            raise RuntimeError(f"VBoxManage failed: {stderr.decode()}")

        return stdout.decode()


class CrucibleController:
    """
    Main Crucible Controller for VM lifecycle management.

    Manages isolated VMs for safe malware execution:
    - Creates VMs from golden images
    - Manages VM lifecycle (start, stop, destroy)
    - Handles snapshots for clean test restores
    - Verifies network isolation before tests
    """

    def __init__(
        self,
        hypervisor_type: HypervisorType = HypervisorType.LIBVIRT,
        **hypervisor_kwargs: Any,
    ):
        self.hypervisor_type = hypervisor_type
        self._backend = self._create_backend(hypervisor_type, hypervisor_kwargs)
        self._instances: dict[str, VMInstance] = {}
        self._lock = asyncio.Lock()

    def _create_backend(
        self,
        hypervisor_type: HypervisorType,
        kwargs: dict[str, Any],
    ) -> HypervisorBackend:
        """Create hypervisor backend based on type."""
        if hypervisor_type == HypervisorType.LIBVIRT:
            return LibvirtBackend(**kwargs)
        elif hypervisor_type == HypervisorType.VIRTUALBOX:
            return VirtualBoxBackend(**kwargs)
        else:
            raise ValueError(f"Unsupported hypervisor: {hypervisor_type}")

    async def create_instance(self, config: VMConfig) -> VMInstance:
        """
        Create a new Crucible VM instance.

        1. Creates VM from golden image
        2. Creates baseline snapshot
        3. Verifies network isolation
        """
        instance_id = str(uuid.uuid4())
        instance = VMInstance(instance_id=instance_id, config=config)

        async with self._lock:
            self._instances[instance_id] = instance

        try:
            # Create VM
            instance.update_state(VMState.CREATING)
            hypervisor_id = await self._backend.create_vm(config)
            instance.hypervisor_id = hypervisor_id

            # Verify isolation
            if config.isolated_network:
                is_isolated = await self._backend.verify_isolation(hypervisor_id)
                if not is_isolated:
                    raise RuntimeError("VM failed network isolation check")

            # Create baseline snapshot
            instance.update_state(VMState.SNAPSHOTTING)
            await self._backend.create_snapshot(hypervisor_id, config.baseline_snapshot)
            instance.current_snapshot = config.baseline_snapshot

            # Final state
            instance.update_state(VMState.STOPPED)

            logger.info(
                f"Created Crucible instance {instance_id}",
                extra={
                    "instance_id": instance_id,
                    "hypervisor_id": hypervisor_id,
                    "config": config.name,
                },
            )

            return instance

        except Exception as e:
            instance.update_state(VMState.ERROR, str(e))
            raise

    async def start_instance(self, instance_id: str) -> VMInstance:
        """Start a stopped Crucible instance."""
        instance = self._get_instance(instance_id)

        if instance.state != VMState.STOPPED:
            raise RuntimeError(f"Cannot start VM in state {instance.state}")

        instance.update_state(VMState.STARTING)

        try:
            await self._backend.start_vm(instance.hypervisor_id)

            # Wait for VM to be running
            for _ in range(instance.config.start_timeout_seconds):
                state = await self._backend.get_vm_state(instance.hypervisor_id)
                if state == VMState.RUNNING:
                    break
                await asyncio.sleep(1)
            else:
                raise RuntimeError("VM start timeout")

            # Get IP address
            instance.ip_address = await self._backend.get_vm_ip(instance.hypervisor_id)
            instance.update_state(VMState.RUNNING)

            return instance

        except Exception as e:
            instance.update_state(VMState.ERROR, str(e))
            raise

    async def stop_instance(self, instance_id: str, force: bool = False) -> VMInstance:
        """Stop a running Crucible instance."""
        instance = self._get_instance(instance_id)

        if instance.state != VMState.RUNNING:
            raise RuntimeError(f"Cannot stop VM in state {instance.state}")

        instance.update_state(VMState.STOPPING)

        try:
            await self._backend.stop_vm(instance.hypervisor_id, force=force)

            # Wait for VM to stop
            for _ in range(instance.config.stop_timeout_seconds):
                state = await self._backend.get_vm_state(instance.hypervisor_id)
                if state == VMState.STOPPED:
                    break
                await asyncio.sleep(1)
            else:
                if not force:
                    # Force stop if graceful shutdown failed
                    await self._backend.stop_vm(instance.hypervisor_id, force=True)

            instance.update_state(VMState.STOPPED)
            instance.ip_address = None

            return instance

        except Exception as e:
            instance.update_state(VMState.ERROR, str(e))
            raise

    async def restore_instance(
        self,
        instance_id: str,
        snapshot_name: Optional[str] = None,
    ) -> VMInstance:
        """
        Restore a Crucible instance to a clean snapshot.

        This is the critical safety mechanism - after every test,
        restore to baseline to ensure no malware persistence.
        """
        instance = self._get_instance(instance_id)
        snapshot = snapshot_name or instance.config.baseline_snapshot

        # Stop VM if running
        if instance.state == VMState.RUNNING:
            await self.stop_instance(instance_id, force=True)

        instance.update_state(VMState.RESTORING)

        try:
            await self._backend.restore_snapshot(instance.hypervisor_id, snapshot)
            instance.current_snapshot = snapshot
            instance.update_state(VMState.STOPPED)

            logger.info(
                f"Restored instance {instance_id} to snapshot {snapshot}",
                extra={"instance_id": instance_id, "snapshot": snapshot},
            )

            return instance

        except Exception as e:
            instance.update_state(VMState.ERROR, str(e))
            raise

    async def destroy_instance(self, instance_id: str) -> None:
        """Destroy a Crucible instance and clean up all resources."""
        instance = self._get_instance(instance_id)

        instance.update_state(VMState.DESTROYING)

        try:
            await self._backend.destroy_vm(instance.hypervisor_id)
            instance.update_state(VMState.DESTROYED)

            async with self._lock:
                del self._instances[instance_id]

            logger.info(
                f"Destroyed Crucible instance {instance_id}",
                extra={"instance_id": instance_id},
            )

        except Exception as e:
            instance.update_state(VMState.ERROR, str(e))
            raise

    async def get_instance(self, instance_id: str) -> VMInstance:
        """Get instance details."""
        instance = self._get_instance(instance_id)

        # Refresh state from hypervisor
        if instance.hypervisor_id:
            state = await self._backend.get_vm_state(instance.hypervisor_id)
            if state != instance.state and state != VMState.UNKNOWN:
                instance.update_state(state)

        return instance

    async def list_instances(self) -> list[VMInstance]:
        """List all managed instances."""
        async with self._lock:
            return list(self._instances.values())

    async def verify_isolation(self, instance_id: str) -> bool:
        """Verify VM network isolation before test execution."""
        instance = self._get_instance(instance_id)
        return await self._backend.verify_isolation(instance.hypervisor_id)

    def _get_instance(self, instance_id: str) -> VMInstance:
        """Get instance or raise error."""
        instance = self._instances.get(instance_id)
        if not instance:
            raise ValueError(f"Unknown instance: {instance_id}")
        return instance
