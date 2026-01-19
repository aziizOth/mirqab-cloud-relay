# Mirqab Cloud Relay - Network Actor OVA Builder
# Packer configuration for building Network Actor base image

packer {
  required_plugins {
    qemu = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/qemu"
    }
    virtualbox = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/virtualbox"
    }
  }
}

# Variables
variable "ubuntu_version" {
  type    = string
  default = "22.04"
}

variable "ubuntu_iso_url" {
  type    = string
  default = "https://releases.ubuntu.com/22.04/ubuntu-22.04.4-live-server-amd64.iso"
}

variable "ubuntu_iso_checksum" {
  type    = string
  default = "sha256:45f873de9f8cb637345d6e66a583762730bbea30277ef7b32c9c3bd6700a32b2"
}

variable "ssh_username" {
  type    = string
  default = "mirqab"
}

variable "ssh_password" {
  type      = string
  default   = "mirqab123"
  sensitive = true
}

variable "vm_name" {
  type    = string
  default = "mirqab-network-actor"
}

variable "disk_size" {
  type    = string
  default = "20G"
}

variable "memory" {
  type    = number
  default = 2048
}

variable "cpus" {
  type    = number
  default = 2
}

# Source: VirtualBox (for OVA export)
source "virtualbox-iso" "network-actor" {
  guest_os_type        = "Ubuntu_64"
  iso_url              = var.ubuntu_iso_url
  iso_checksum         = var.ubuntu_iso_checksum
  ssh_username         = var.ssh_username
  ssh_password         = var.ssh_password
  ssh_timeout          = "30m"
  shutdown_command     = "echo '${var.ssh_password}' | sudo -S shutdown -P now"
  vm_name              = var.vm_name
  disk_size            = var.disk_size
  memory               = var.memory
  cpus                 = var.cpus
  headless             = true
  format               = "ova"

  # Boot command for autoinstall
  boot_command = [
    "c<wait>",
    "linux /casper/vmlinuz ",
    "autoinstall ds=nocloud-net\\;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/ ",
    "--- <enter><wait>",
    "initrd /casper/initrd<enter><wait>",
    "boot<enter>"
  ]

  http_directory = "http"
  boot_wait      = "5s"

  vboxmanage = [
    ["modifyvm", "{{.Name}}", "--nat-localhostreachable1", "on"],
  ]
}

# Source: QEMU (for local testing)
source "qemu" "network-actor" {
  iso_url           = var.ubuntu_iso_url
  iso_checksum      = var.ubuntu_iso_checksum
  ssh_username      = var.ssh_username
  ssh_password      = var.ssh_password
  ssh_timeout       = "30m"
  shutdown_command  = "echo '${var.ssh_password}' | sudo -S shutdown -P now"
  vm_name           = var.vm_name
  disk_size         = var.disk_size
  memory            = var.memory
  cpus              = var.cpus
  headless          = true
  format            = "qcow2"
  accelerator       = "kvm"

  boot_command = [
    "c<wait>",
    "linux /casper/vmlinuz ",
    "autoinstall ds=nocloud-net\\;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/ ",
    "--- <enter><wait>",
    "initrd /casper/initrd<enter><wait>",
    "boot<enter>"
  ]

  http_directory = "http"
  boot_wait      = "5s"
}

# Build configuration
build {
  sources = [
    "source.virtualbox-iso.network-actor",
    # "source.qemu.network-actor",  # Uncomment for QEMU builds
  ]

  # Wait for cloud-init to complete
  provisioner "shell" {
    inline = [
      "while [ ! -f /var/lib/cloud/instance/boot-finished ]; do sleep 1; done"
    ]
  }

  # Install base packages
  provisioner "shell" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get install -y software-properties-common",
      "sudo apt-get install -y python3 python3-pip python3-venv",
      "sudo apt-get install -y ufw iptables",
      "sudo apt-get install -y samba openssh-server nginx",
      "sudo apt-get install -y curl wget jq",
    ]
  }

  # Disable services by default (will be started on-demand)
  provisioner "shell" {
    inline = [
      "sudo systemctl disable smbd || true",
      "sudo systemctl stop smbd || true",
      "sudo systemctl disable nginx || true",
      "sudo systemctl stop nginx || true",
      "sudo systemctl enable ssh",  # SSH stays enabled for management
    ]
  }

  # Copy Network Actor agent code
  provisioner "file" {
    source      = "../src/"
    destination = "/tmp/network-actor-src/"
  }

  # Install Network Actor agent
  provisioner "shell" {
    inline = [
      "sudo mkdir -p /opt/mirqab/network-actor",
      "sudo cp -r /tmp/network-actor-src/* /opt/mirqab/network-actor/",
      "cd /opt/mirqab/network-actor",
      "sudo python3 -m venv venv",
      "sudo /opt/mirqab/network-actor/venv/bin/pip install --upgrade pip",
      "sudo /opt/mirqab/network-actor/venv/bin/pip install httpx aiofiles",
      "sudo chown -R root:root /opt/mirqab",
    ]
  }

  # Create systemd service
  provisioner "file" {
    content = <<-EOF
    [Unit]
    Description=Mirqab Network Actor Agent
    After=network.target

    [Service]
    Type=simple
    User=root
    WorkingDirectory=/opt/mirqab/network-actor
    Environment=PYTHONPATH=/opt/mirqab/network-actor
    ExecStart=/opt/mirqab/network-actor/venv/bin/python -m src.network_actor_agent
    Restart=always
    RestartSec=10

    [Install]
    WantedBy=multi-user.target
    EOF
    destination = "/tmp/mirqab-network-actor.service"
  }

  provisioner "shell" {
    inline = [
      "sudo mv /tmp/mirqab-network-actor.service /etc/systemd/system/",
      "sudo systemctl daemon-reload",
      "sudo systemctl enable mirqab-network-actor",
    ]
  }

  # Configure firewall (default deny all except SSH)
  provisioner "shell" {
    inline = [
      "sudo ufw default deny incoming",
      "sudo ufw default allow outgoing",
      "sudo ufw allow ssh",
      "sudo ufw --force enable",
    ]
  }

  # Create configuration directory
  provisioner "shell" {
    inline = [
      "sudo mkdir -p /etc/mirqab",
      "sudo mkdir -p /var/log/mirqab-network-actor",
      "sudo chown root:root /etc/mirqab",
      "sudo chmod 700 /etc/mirqab",
    ]
  }

  # Create configuration template
  provisioner "file" {
    content = <<-EOF
    # Mirqab Network Actor Configuration
    # Copy this file to /etc/mirqab/network-actor.env and configure

    # Master server connection
    MASTER_URL=https://api.offensight.local:8000
    TENANT_ID=your-tenant-id
    API_KEY=your-api-key

    # Agent identity
    AGENT_ID=network-actor-001
    AGENT_NAME=Network Actor

    # Timeouts
    DEFAULT_TIMEOUT=300
    MAX_TIMEOUT=3600

    # Polling
    POLL_INTERVAL=5.0

    # Logging
    LOG_DIR=/var/log/mirqab-network-actor
    EOF
    destination = "/tmp/network-actor.env.template"
  }

  provisioner "shell" {
    inline = [
      "sudo mv /tmp/network-actor.env.template /etc/mirqab/network-actor.env.template",
    ]
  }

  # Clean up
  provisioner "shell" {
    inline = [
      "sudo apt-get clean",
      "sudo rm -rf /var/lib/apt/lists/*",
      "sudo rm -rf /tmp/*",
      "sudo rm -f /etc/ssh/ssh_host_*",  # Regenerated on first boot
    ]
  }

  # OVA export settings
  post-processor "manifest" {
    output = "manifest.json"
  }
}
