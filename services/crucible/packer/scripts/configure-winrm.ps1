# Configure WinRM for Packer Provisioning
# This script enables WinRM for automated provisioning during image build

Write-Host "Configuring WinRM for Packer..."

# Set network profile to Private (required for WinRM)
$networkProfile = Get-NetConnectionProfile
Set-NetConnectionProfile -Name $networkProfile.Name -NetworkCategory Private

# Enable PowerShell remoting
Enable-PSRemoting -Force -SkipNetworkProfileCheck

# Configure WinRM service
winrm quickconfig -force
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/client/auth '@{Basic="true"}'

# Set WinRM to start automatically
Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM

# Configure firewall for WinRM
netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in localport=5985 protocol=TCP action=allow
netsh advfirewall firewall add rule name="WinRM-HTTPS" dir=in localport=5986 protocol=TCP action=allow

# Increase WinRM limits for large file transfers
winrm set winrm/config '@{MaxTimeoutms="7200000"}'
winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="2048"}'

Write-Host "WinRM configuration complete"

# Restart WinRM to apply changes
Restart-Service WinRM

Write-Host "WinRM is ready for Packer provisioning"
