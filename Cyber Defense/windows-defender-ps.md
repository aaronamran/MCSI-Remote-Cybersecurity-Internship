# Write A PS Script To Turn On Windows Defender
Windows Defender, pre-installed on Windows 10, protects against malware and online threats. Its "Real-time Protection" feature continuously monitors for infections and suspends suspicious programs automatically.


## References
- [Manage Windows Defender using PowerShell](https://learn.microsoft.com/en-us/archive/technet-wiki/52251.manage-windows-defender-using-powershell) by Microsoft
- [Running Remote Commands](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/running-remote-commands?view=powershell-7.4&viewFallbackFrom=powershell-7) by Microsoft
- [Resolving "Access is Denied" Errors in Assets Discovery Tool with PowerShell patterns](https://confluence.atlassian.com/jirakb/resolving-access-is-denied-errors-in-assets-discovery-tool-with-powershell-patterns-1402421369.html) by Atlassian
- [Enter-PSSession: receiving access denied on non domain remote server](https://serverfault.com/questions/1117959/enter-pssession-receiving-access-denied-on-non-domain-remote-server) by Abid on serverfault
- [How to Disable, Enable, and Manage Microsoft Defender Using PowerShell?](https://theitbros.com/managing-windows-defender-using-powershell/) by Cyril Kardashevsky
  

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
    # Ensure the script is running as administrator
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "This script must be run as Administrator!" -ForegroundColor Red
        exit
    }
    
    function Check-And-Enable-Defender {
        param (
            [string[]]$RemoteComputers
        )
    
        foreach ($computer in $RemoteComputers) {
            Write-Host "Processing: $computer" -ForegroundColor Cyan
    
            try {
                if ($computer -eq "localhost") {
                    # Check and enable Defender on the local machine
                    Process-Local-Defender
                } else {
                    # Check and enable Defender on a remote machine
                    $credentials = Get-Credential
                    Process-Remote-Defender -ComputerName $computer -Credential $credentials
                }
            } catch {
                Write-Host "Error processing $computer" -ForegroundColor Red
            }
        }
    }
    
    function Process-Local-Defender {
        try {
            # Ensure the Defender service is running
            $service = Get-Service -Name WinDefend -ErrorAction Stop
            if ($service.Status -ne "Running") {
                Write-Host "Starting Windows Defender service locally..." -ForegroundColor Yellow
                Set-Service -Name WinDefend -StartupType Automatic
                Start-Service -Name WinDefend
            }
    
            # Check and enable real-time protection
            $DefenderStatus = Get-MpPreference
            if ($DefenderStatus.DisableRealtimeMonitoring -eq $false) {
                Write-Host "Windows Defender real-time protection is already enabled." -ForegroundColor Green
            } else {
                Write-Host "Enabling Windows Defender real-time protection locally..." -ForegroundColor Yellow
                Set-MpPreference -DisableRealtimeMonitoring $false
                Write-Host "Real-time protection enabled." -ForegroundColor Green
            }
    
        } catch {
            Write-Host "Error enabling Defender locally" -ForegroundColor Red
        }
    }
    
    function Process-Remote-Defender {
        param (
            [string]$ComputerName,
            [pscredential]$Credential
        )
        try {
            # Create a remote session with Basic authentication
            $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -Authentication Basic -ErrorAction Stop
    
            # Check Defender status on the remote machine
            Invoke-Command -Session $session -ScriptBlock {
                try {
                    # Get Defender status
                    $DefenderStatus = Get-MpPreference
    
                    # Check real-time protection
                    if ($DefenderStatus.DisableRealtimeMonitoring -eq $false) {
                        Write-Host "Real-time protection is already enabled on $env:COMPUTERNAME." -ForegroundColor Green
                    } else {
                        Write-Host "Real-time protection is disabled on $env:COMPUTERNAME. Enabling now..." -ForegroundColor Yellow
                        Set-MpPreference -DisableRealtimeMonitoring $false
                        Write-Host "Real-time protection enabled on $env:COMPUTERNAME." -ForegroundColor Green
                    }
    
                    # Check cloud-delivered protection
                    if ($DefenderStatus.MAPSReporting -eq 2) {
                        Write-Host "Cloud-delivered protection is already enabled on $env:COMPUTERNAME." -ForegroundColor Green
                    } else {
                        Write-Host "Cloud-delivered protection is not fully enabled on $env:COMPUTERNAME. Enabling now..." -ForegroundColor Yellow
                        Set-MpPreference -MAPSReporting Advanced
                        Write-Host "Cloud-delivered protection enabled on $env:COMPUTERNAME." -ForegroundColor Green
                    }
    
                } catch {
                    Write-Host "Error checking or enabling Defender status on $env:COMPUTERNAME" -ForegroundColor Red
                }
            }
    
            # Remove the session
            Remove-PSSession -Session $session
        } catch {
            Write-Host "Error enabling Defender on $ComputerName" -ForegroundColor Red
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
   Set-Item WSMan:\localhost\Client\TrustedHosts -Value "the_other_Windows_IP_Address1,the_other_Windows_IP_Address2"
   Set-Item -force WSMan:\localhost\Client\AllowUnencrypted $true
   Set-Item -force WSMan:\localhost\Service\AllowUnencrypted $true
   Set-Item -force WSMan:\localhost\Client\Auth\Digest $true
   Set-Item -force WSMan:\localhost\Service\Auth\Basic $true
   ```
4. To test the PowerShell remoting capability, use
   ```
   Enter-PSSession -ComputerName the_other_Windows_IP_Address -Authentication Basic -Credential (Get-Credential)
   ```
5. To allow PowerShell scripts to change the state of the Real-time protection in Windows, Tamper Protection must be turned off first
   ![image](https://github.com/user-attachments/assets/c3797063-14f5-4a93-8830-8218c61e4f48)
6. Enable Windows Defender on the local Windows 11 machine and run the script
   ![image](https://github.com/user-attachments/assets/52d5d513-3d92-4dc4-b815-365611acd3a0)
7. Disable Windows Defender on the local Windows 11 machine and run the script again
   ![image](https://github.com/user-attachments/assets/5e33a5ba-0515-4517-ab01-fc753ebe0078)
8. Enable Windows Defender on the first remote Windows 10 VM and disable Windows Defender on the second remote Windows 10 VM
9. Run the script to target 


