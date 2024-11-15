# Write A PS Script To Turn On Windows Defender
Windows Defender, pre-installed on Windows 10, protects against malware and online threats. Its "Real-time Protection" feature continuously monitors for infections and suspends suspicious programs automatically.


## References
- [Manage Windows Defender using PowerShell](https://learn.microsoft.com/en-us/archive/technet-wiki/52251.manage-windows-defender-using-powershell) by Microsoft
- [Running Remote Commands](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/running-remote-commands?view=powershell-7.4&viewFallbackFrom=powershell-7) by Microsoft
- [Resolving "Access is Denied" Errors in Assets Discovery Tool with PowerShell patterns](https://confluence.atlassian.com/jirakb/resolving-access-is-denied-errors-in-assets-discovery-tool-with-powershell-patterns-1402421369.html) by Atlassian
- [Enter-PSSession: receiving access denied on non domain remote server](https://serverfault.com/questions/1117959/enter-pssession-receiving-access-denied-on-non-domain-remote-server) by Abid on serverfault
  

## PowerShell Script Requirements
- Checks the current status of the Windows Defender on a local machine
- If Windows Defender is enabled, displays a message indicating that it is already enabled
- If Windows Defender is not enabled, proceeds to enable it
- Implements the logic to turn on the Windows Defender programmatically
- After enabling Windows Defender, includes the logic to force it to update itself
- Displays a success message once Windows Defender is enabled and updated
- Supports remote machines
- Accepts a list of remote machine names or IP addresses as input



## Recommended Approach
- Enable your Windows Defender
- Run the script on your local machine
- Disable your Windows Defender
- Run the script again on your local machine
- Start up two (2) Windows virtual machines
- Enable Windows Defender on 1 machine
- Disable Windows Defender on the other machine
- Create a list containing the remote machine addresses
- Scan/fix the remote hosts by passing the list to your tool


## Benchmarks
- Defender Enabled locally: The script running on your local machine correctly detects Windows Defender status as enabled
- Defender Disabled locally: The script running on your local machine enables Windows Defender and updates itself
- Ensure that real-time protection is enabled after turning on Windows Defender
- The remote hosts list scan detects Windows Defender enabled on one machine
- The remote hosts list scan enables Windows Defender on the vulnerable machine and updates itself


## Solutions With Scripts
1. Save and run the following PowerShell script as `enable-defender.ps1` on Windows 11 machine. Note that this task can only be completed among Windows 10 and 11 machines
   ```
   # Script to check and enable Windows Defender with real-time protection, both locally and remotely

    function Check-And-Enable-Defender {
        param (
            [string[]]$RemoteComputers
        )
    
        foreach ($computer in $RemoteComputers) {
            Write-Host "Processing: $computer" -ForegroundColor Cyan
    
            try {
                if ($computer -eq "localhost") {
                    # Local machine
                    $DefenderStatus = Get-MpPreference
                } else {
                    # Remote machine
                    $session = New-PSSession -ComputerName $computer -ErrorAction Stop
                    $DefenderStatus = Invoke-Command -Session $session -ScriptBlock { Get-MpPreference }
                }
    
                if ($DefenderStatus.DisableRealtimeMonitoring -eq $false) {
                    Write-Host "Windows Defender is already enabled on $computer." -ForegroundColor Green
                } else {
                    Write-Host "Windows Defender is disabled on $computer. Enabling..." -ForegroundColor Yellow
    
                    if ($computer -eq "localhost") {
                        # Enable Windows Defender locally
                        Set-MpPreference -DisableRealtimeMonitoring $false
                        Start-MpWDOScan -ScanType QuickScan
                    } else {
                        # Enable Windows Defender remotely
                        Invoke-Command -Session $session -ScriptBlock { 
                            Set-MpPreference -DisableRealtimeMonitoring $false
                            Start-MpWDOScan -ScanType QuickScan
                        }
                    }
    
                    # Force update definitions
                    if ($computer -eq "localhost") {
                        Update-MpSignature
                    } else {
                        Invoke-Command -Session $session -ScriptBlock { Update-MpSignature }
                    }
    
                    Write-Host "Windows Defender has been enabled and updated on $computer." -ForegroundColor Green
                }
    
            } catch {
                Write-Host "Error processing $computer: $_" -ForegroundColor Red
            } finally {
                if ($session) { Remove-PSSession -Session $session }
            }
        }
    }
    
    # Main script logic
    Write-Host "Windows Defender Management Script" -ForegroundColor Cyan
    Write-Host "Enter a list of computer names or IP addresses (separated by commas):"
    $inputComputers = Read-Host "Example: localhost, 192.168.1.10, RemotePC"
    
    # Parse input into array
    $computerList = $inputComputers -split ',' | ForEach-Object { $_.Trim() }
    
    # Check and enable Defender
    Check-And-Enable-Defender -RemoteComputers $computerList
   ```
2. Set Execution Policy (if necessary): If you encounter a script execution error, use the following command to allow the script to run:
   ```
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
3. To enable PowerShell remoting between local and target VMs, get the IP address of the target remote machine. Then set it as a trusted host on the local machine to allow remote connections
   ```
   winrm quickconfig -Force
   Enable-PSRemoting -Force
   Set-Item WSMan:\localhost\Client\TrustedHosts -Value "the_other_Windows_IP_Address"
   Set-Item -force WSMan:\localhost\Client\AllowUnencrypted $true
   Set-Item -force WSMan:\localhost\Service\AllowUnencrypted $true
   Set-Item -force WSMan:\localhost\Client\Auth\Digest $true
   Set-Item -force WSMan:\localhost\Service\Auth\Basic $true
   ```
4. To test the PowerShell remoting capability, use
   ```
   Enter-PSSession -ComputerName the_other_Windows_IP_Address -Authentication Basic -Credential (Get-Credential)
   ```
5. Enable Windows Defender on the local Windows 11 machine and run the script
6. Disable Windows Defender on the local Windows 11 machine and run the script again
7. Enable Windows Defender on the first remote Windows 10 VM and disable Windows Defender on the second remote Windows 10 VM
8. Run the script to target both Windows 10 VMs


