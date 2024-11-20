# Write A PS Script To Turn On Hyper-V
Hyper-V, Microsoft's hypervisor, enables multiple operating systems to run on one physical machine. It enhances cybersecurity by protecting against memory-based credential theft (e.g., `lsass.exe`) and can block tools like Mimikatz, adding an extra layer of defense.

## References
- [Windows 10 Device Guard and Credential Guard Demystified](https://learn.microsoft.com/en-us/archive/blogs/ash/windows-10-device-guard-and-credential-guard-demystified) by Microsoft
- [Isolated User Mode (IUM) Processes](https://learn.microsoft.com/en-us/windows/win32/procthread/isolated-user-mode--ium--processes) by Microsoft

## Tasks
- Write a PowerShell script to check if Hyper-V is enabled by querying the appropriate Windows feature
- Display a message indicating whether Hyper-V is enabled or disabled
- Use PowerShell commands to enable Hyper-V on the local machine
- Display a success message after enabling Hyper-V
- Provide an option in the script to force a reboot

## Practical Approach
[Link to the complete PowerShell script](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Cyber%20Defense/scripts/controlhyperv.ps1)

```
# Write A PS Script To Turn On Hyper-V

# Store PowerShell cmdlet with parameters into a variable
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

1. Open Notepad, paste the script, and save it as a .ps1 file (e.g., ManageHyperV.ps1).
2. Open PowerShell as Administrator.
3. Navigate to the folder where the script is saved using cd path\to\script.
4. Run the script in PowerShell `./ManageHyperV.ps1` 
5. Set Execution Policy (if necessary): If you encounter a script execution error, use the following command to allow the script to run:
    ```
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    ```
6. To disable Hyper-V in PowerShell, run the following command or add it to the beginning of the PowerShell script:
   ```
   Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
   ```
   And to check if Hyper-V is disabled, run:
   ```
   Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
   ```
7. Alternatively, Hyper-V can be manually disabled in "Turn Windows features on or off" options.
