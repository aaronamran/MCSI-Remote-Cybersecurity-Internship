# Write A PS Script To Turn On Hyper-V
Hyper-V, Microsoft's hypervisor, enables multiple operating systems to run on one physical machine. It enhances cybersecurity by protecting against memory-based credential theft (e.g., `lsass.exe`) and can block tools like Mimikatz, adding an extra layer of defense.

## Tasks
- Write a PowerShell script to check if Hyper-V is enabled by querying the appropriate Windows feature
- Display a message indicating whether Hyper-V is enabled or disabled
- Use PowerShell commands to enable Hyper-V on the local machine
- Display a success message after enabling Hyper-V
- Provide an option in the script to force a reboot

## PowerShell Script
```
# Check if Hyper-V is enabled
$hyperVStatus = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All

# Function to enable Hyper-V
function Enable-HyperV {
    Write-Host "Enabling Hyper-V..." -ForegroundColor Yellow
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart
    Write-Host "Hyper-V has been enabled." -ForegroundColor Green
    # Ask if the user wants to reboot now
    $reboot = Read-Host "Would you like to restart now? (Y/N)"
    if ($reboot -eq "Y" -or $reboot -eq "y") {
        Write-Host "Rebooting the system..." -ForegroundColor Cyan
        Restart-Computer -Force
    } else {
        Write-Host "You can restart the system later for changes to take effect." -ForegroundColor Cyan
    }
}

# Check the current status of Hyper-V and act accordingly
if ($hyperVStatus.State -eq "Enabled") {
    Write-Host "Hyper-V is already enabled on this system." -ForegroundColor Green
} else {
    Write-Host "Hyper-V is disabled on this system." -ForegroundColor Red
    $enable = Read-Host "Would you like to enable Hyper-V? (Y/N)"
    if ($enable -eq "Y" -or $enable -eq "y") {
        Enable-HyperV
    } else {
        Write-Host "Hyper-V will remain disabled." -ForegroundColor Yellow
    }
}
```

Type the code in notepad and save as `.ps1` file type
