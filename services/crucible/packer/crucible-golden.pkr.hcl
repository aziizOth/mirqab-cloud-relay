# Crucible Golden Image - Windows 10 Test Environment
#
# This Packer template builds the base VM image for Crucible testing.
# The golden image includes:
# - Windows 10 with latest updates
# - Crucible Agent pre-installed
# - Placeholder for customer's EDR/AV solution
# - Network isolation preconfigured
#
# Build: packer build -var "iso_path=./windows10.iso" crucible-golden.pkr.hcl

packer {
  required_plugins {
    virtualbox = {
      source  = "github.com/hashicorp/virtualbox"
      version = ">= 1.0.0"
    }
    vmware = {
      source  = "github.com/hashicorp/vmware"
      version = ">= 1.0.0"
    }
  }
}

# Variables
variable "iso_path" {
  type        = string
  description = "Path to Windows 10 ISO"
}

variable "iso_checksum" {
  type        = string
  description = "SHA256 checksum of Windows ISO"
  default     = ""
}

variable "output_directory" {
  type        = string
  description = "Output directory for OVA"
  default     = "output-crucible"
}

variable "vm_name" {
  type        = string
  description = "Name for the VM"
  default     = "crucible-golden"
}

variable "cpu_count" {
  type        = number
  description = "Number of CPUs"
  default     = 2
}

variable "memory_mb" {
  type        = number
  description = "Memory in MB"
  default     = 4096
}

variable "disk_size_mb" {
  type        = number
  description = "Disk size in MB"
  default     = 40960
}

variable "winrm_username" {
  type        = string
  description = "WinRM username for provisioning"
  default     = "crucible"
}

variable "winrm_password" {
  type        = string
  description = "WinRM password for provisioning"
  default     = "CrucibleTest123!"
  sensitive   = true
}

variable "controller_url" {
  type        = string
  description = "Crucible Controller URL"
  default     = "https://crucible-controller:9443"
}

variable "agent_api_key" {
  type        = string
  description = "API key for Crucible Agent"
  default     = ""
  sensitive   = true
}

# VirtualBox builder
source "virtualbox-iso" "crucible-windows" {
  guest_os_type        = "Windows10_64"
  iso_url              = var.iso_path
  iso_checksum         = var.iso_checksum
  output_directory     = "${var.output_directory}-vbox"
  vm_name              = var.vm_name
  format               = "ova"

  cpus                 = var.cpu_count
  memory               = var.memory_mb
  disk_size            = var.disk_size_mb

  # Network configuration - internal only
  vboxmanage = [
    ["modifyvm", "{{.Name}}", "--nic1", "intnet"],
    ["modifyvm", "{{.Name}}", "--intnet1", "crucible-isolated"],
    ["modifyvm", "{{.Name}}", "--natpf1", "delete", "winrm"],
  ]

  # Temporarily enable NAT for provisioning
  vboxmanage_post = [
    ["modifyvm", "{{.Name}}", "--nic1", "intnet"],
    ["modifyvm", "{{.Name}}", "--intnet1", "crucible-isolated"],
  ]

  communicator         = "winrm"
  winrm_username       = var.winrm_username
  winrm_password       = var.winrm_password
  winrm_timeout        = "2h"

  shutdown_command     = "shutdown /s /t 10 /f /d p:4:1 /c \"Packer Shutdown\""
  shutdown_timeout     = "15m"

  # Autounattend for automated Windows installation
  floppy_files = [
    "answer_files/autounattend.xml",
    "scripts/configure-winrm.ps1",
    "scripts/install-agent.ps1",
  ]

  boot_wait = "5s"
}

# VMware builder
source "vmware-iso" "crucible-windows" {
  guest_os_type        = "windows9-64"
  iso_url              = var.iso_path
  iso_checksum         = var.iso_checksum
  output_directory     = "${var.output_directory}-vmware"
  vm_name              = var.vm_name
  format               = "ova"

  cpus                 = var.cpu_count
  memory               = var.memory_mb
  disk_size            = var.disk_size_mb
  disk_type_id         = "0"

  # Network - will be configured as isolated post-build
  network_adapter_type = "e1000e"
  network              = "nat"  # Temporary for provisioning

  communicator         = "winrm"
  winrm_username       = var.winrm_username
  winrm_password       = var.winrm_password
  winrm_timeout        = "2h"

  shutdown_command     = "shutdown /s /t 10 /f /d p:4:1 /c \"Packer Shutdown\""
  shutdown_timeout     = "15m"

  floppy_files = [
    "answer_files/autounattend.xml",
    "scripts/configure-winrm.ps1",
    "scripts/install-agent.ps1",
  ]

  boot_wait = "5s"
}

# Build configuration
build {
  name = "crucible-golden"

  sources = [
    "source.virtualbox-iso.crucible-windows",
    "source.vmware-iso.crucible-windows",
  ]

  # Wait for Windows to fully boot
  provisioner "powershell" {
    inline = [
      "Write-Host 'Waiting for Windows to be ready...'",
      "Start-Sleep -Seconds 30",
    ]
  }

  # Install Windows updates
  provisioner "powershell" {
    inline = [
      "Write-Host 'Installing Windows Updates...'",
      "Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force",
      "Install-Module -Name PSWindowsUpdate -Force",
      "Get-WindowsUpdate -AcceptAll -Install -AutoReboot",
    ]
  }

  # Install Python for Crucible Agent
  provisioner "powershell" {
    inline = [
      "Write-Host 'Installing Python...'",
      "$pythonUrl = 'https://www.python.org/ftp/python/3.11.0/python-3.11.0-amd64.exe'",
      "$pythonInstaller = 'C:\\python-installer.exe'",
      "Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller",
      "Start-Process -Wait -FilePath $pythonInstaller -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1'",
      "Remove-Item $pythonInstaller",
      "refreshenv",
    ]
  }

  # Copy Crucible Agent files
  provisioner "file" {
    source      = "../src/"
    destination = "C:\\Program Files\\Crucible\\src\\"
  }

  provisioner "file" {
    source      = "../requirements.txt"
    destination = "C:\\Program Files\\Crucible\\requirements.txt"
  }

  # Install Crucible Agent
  provisioner "powershell" {
    inline = [
      "Write-Host 'Installing Crucible Agent...'",
      "Set-Location 'C:\\Program Files\\Crucible'",
      "python -m pip install --upgrade pip",
      "python -m pip install -r requirements.txt",
    ]
  }

  # Configure Crucible Agent service
  provisioner "powershell" {
    environment_vars = [
      "CRUCIBLE_CONTROLLER_URL=${var.controller_url}",
      "CRUCIBLE_API_KEY=${var.agent_api_key}",
    ]
    inline = [
      "Write-Host 'Configuring Crucible Agent service...'",
      "",
      "# Create agent configuration",
      "$configDir = 'C:\\ProgramData\\Crucible'",
      "New-Item -ItemType Directory -Force -Path $configDir",
      "",
      "$config = @{",
      "    controller_url = $env:CRUCIBLE_CONTROLLER_URL",
      "    api_key = $env:CRUCIBLE_API_KEY",
      "    agent_id = 'PLACEHOLDER_AGENT_ID'  # Set at deployment",
      "    listen_port = 9443",
      "    work_dir = 'C:\\ProgramData\\Crucible\\work'",
      "}",
      "$config | ConvertTo-Json | Set-Content \"$configDir\\config.json\"",
      "",
      "# Create Windows service",
      "$serviceName = 'CrucibleAgent'",
      "$serviceDisplayName = 'Crucible Test Agent'",
      "$serviceDescription = 'Isolated malware execution agent for EDR testing'",
      "$servicePath = '\"C:\\Program Files\\Python311\\python.exe\" -m crucible.agent'",
      "",
      "New-Service -Name $serviceName -BinaryPathName $servicePath -DisplayName $serviceDisplayName -Description $serviceDescription -StartupType Manual",
      "",
      "Write-Host 'Crucible Agent service created'",
    ]
  }

  # Disable Windows Defender (customer will install their own EDR)
  provisioner "powershell" {
    inline = [
      "Write-Host 'Disabling Windows Defender (customer will install their EDR)...'",
      "Set-MpPreference -DisableRealtimeMonitoring $true",
      "Set-MpPreference -DisableBehaviorMonitoring $true",
      "Set-MpPreference -DisableBlockAtFirstSeen $true",
      "Set-MpPreference -DisableIOAVProtection $true",
      "Set-MpPreference -DisablePrivacyMode $true",
      "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true",
      "Set-MpPreference -DisableArchiveScanning $true",
      "Set-MpPreference -DisableIntrusionPreventionSystem $true",
      "Set-MpPreference -DisableScriptScanning $true",
      "",
      "# Add exclusion for Crucible work directory",
      "Add-MpPreference -ExclusionPath 'C:\\ProgramData\\Crucible'",
      "",
      "Write-Host 'Defender disabled - install customer EDR before testing'",
    ]
  }

  # Configure firewall for isolation
  provisioner "powershell" {
    inline = [
      "Write-Host 'Configuring firewall for isolation...'",
      "",
      "# Block all outbound by default",
      "Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block",
      "",
      "# Allow Crucible Agent port (inbound from controller)",
      "New-NetFirewallRule -DisplayName 'Crucible Agent' -Direction Inbound -LocalPort 9443 -Protocol TCP -Action Allow",
      "",
      "# Allow internal network only",
      "New-NetFirewallRule -DisplayName 'Crucible Internal' -Direction Outbound -RemoteAddress 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 -Action Allow",
      "",
      "Write-Host 'Firewall configured for isolation'",
    ]
  }

  # Create isolation verification script
  provisioner "powershell" {
    inline = [
      "Write-Host 'Creating isolation verification script...'",
      "",
      "$script = @'",
      "# Crucible Isolation Verification",
      "Write-Host \"Verifying network isolation...\"",
      "",
      "# Test 1: Cannot resolve external DNS",
      "$dnsTest = $false",
      "try {",
      "    Resolve-DnsName google.com -ErrorAction Stop",
      "    Write-Host \"FAIL: DNS resolution working - NOT ISOLATED\" -ForegroundColor Red",
      "} catch {",
      "    Write-Host \"PASS: DNS blocked\" -ForegroundColor Green",
      "    $dnsTest = $true",
      "}",
      "",
      "# Test 2: Cannot ping external IP",
      "$pingTest = $false",
      "try {",
      "    $result = Test-Connection 8.8.8.8 -Count 1 -Quiet -ErrorAction Stop",
      "    if (-not $result) {",
      "        Write-Host \"PASS: External ping blocked\" -ForegroundColor Green",
      "        $pingTest = $true",
      "    } else {",
      "        Write-Host \"FAIL: External ping succeeded - NOT ISOLATED\" -ForegroundColor Red",
      "    }",
      "} catch {",
      "    Write-Host \"PASS: External ping blocked\" -ForegroundColor Green",
      "    $pingTest = $true",
      "}",
      "",
      "# Test 3: Cannot establish external TCP connection",
      "$tcpTest = $false",
      "try {",
      "    $tcp = New-Object System.Net.Sockets.TcpClient",
      "    $tcp.Connect(\"1.1.1.1\", 443)",
      "    $tcp.Close()",
      "    Write-Host \"FAIL: TCP connection succeeded - NOT ISOLATED\" -ForegroundColor Red",
      "} catch {",
      "    Write-Host \"PASS: TCP blocked\" -ForegroundColor Green",
      "    $tcpTest = $true",
      "}",
      "",
      "if ($dnsTest -and $pingTest -and $tcpTest) {",
      "    Write-Host \"\"",
      "    Write-Host \"ISOLATION VERIFIED\" -ForegroundColor Green",
      "    exit 0",
      "} else {",
      "    Write-Host \"\"",
      "    Write-Host \"ISOLATION FAILED - DO NOT RUN TESTS\" -ForegroundColor Red",
      "    exit 1",
      "}",
      "'@",
      "",
      "$script | Set-Content 'C:\\Program Files\\Crucible\\verify-isolation.ps1'",
    ]
  }

  # Clean up for smaller image
  provisioner "powershell" {
    inline = [
      "Write-Host 'Cleaning up...'",
      "",
      "# Clear temp files",
      "Remove-Item -Recurse -Force $env:TEMP\\* -ErrorAction SilentlyContinue",
      "Remove-Item -Recurse -Force C:\\Windows\\Temp\\* -ErrorAction SilentlyContinue",
      "",
      "# Clear event logs",
      "wevtutil cl System",
      "wevtutil cl Application",
      "wevtutil cl Security",
      "",
      "# Defrag and compact (reduces OVA size)",
      "Optimize-Volume -DriveLetter C -Defrag -Verbose",
      "",
      "Write-Host 'Cleanup complete'",
    ]
  }

  # Final message
  provisioner "powershell" {
    inline = [
      "Write-Host ''",
      "Write-Host '========================================' -ForegroundColor Cyan",
      "Write-Host 'Crucible Golden Image Build Complete' -ForegroundColor Cyan",
      "Write-Host '========================================' -ForegroundColor Cyan",
      "Write-Host ''",
      "Write-Host 'Before using this image:' -ForegroundColor Yellow",
      "Write-Host '1. Install customer EDR/AV solution'",
      "Write-Host '2. Set unique AGENT_ID in config.json'",
      "Write-Host '3. Verify network isolation with verify-isolation.ps1'",
      "Write-Host '4. Create baseline snapshot'",
      "Write-Host ''",
    ]
  }

  # Post-processing - create OVA
  post-processor "manifest" {
    output     = "${var.output_directory}/manifest.json"
    strip_path = true
  }
}
