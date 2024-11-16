# Write A PS Script To Turn On Automatic Sample Submission
Automatic Sample Submission is a valuable feature in Windows Defender Antivirus that allows the system to send unknown executable files to Microsoft's cloud-based malware analysis infrastructure. This feature enhances the overall security of the system by helping Microsoft detect new malware variants and create more effective security detections

## References
- [Set-MpPreference](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps&viewFallbackFrom=win10-ps)


## Tasks
- Write a PowerShell script that enables the Automatic Sample Submission feature in Windows Defender on the local machine
- Ensure that the script turns on Automatic Sample Submission if it is currently disabled
- Display a success message after enabling the feature
- Extend the script to support remote machines
- Allow the script to accept a list of remote machine names or IP addresses as input
- If a remote machine is specified, the script should remotely check the status of Automatic Sample Submission and enable it if necessary


## Benchmarks
- Disable Automatic Sample Submission on a local machine
- Run the script and demonstrate that it correctly detects and enables Automatic Sample Submission on the local machine
- Disable Automatic Sample Submission on a remote machine
- Run the script and demonstrate that it correctly detects and enables Automatic Sample Submission on the remote machine


## Solutions With Scripts
1. Save the PowerShell script below as `autosamplesubmission.ps1`
    ```
    # Enable Automatic Sample Submission on Windows Defender
    function Enable-AutomaticSampleSubmission {
        param (
            [string[]]$RemoteComputers = @(),
            [pscredential]$Credential = $null
        )
    
        if ($RemoteComputers -contains "localhost") {
            # Local machine
            Write-Host "Checking and enabling Automatic Sample Submission on the local machine..." -ForegroundColor Yellow
            try {
                $currentSetting = (Get-MpPreference).SubmitSamplesConsent
                if ($currentSetting -ne 1) {
                    Set-MpPreference -SubmitSamplesConsent 1
                    Write-Host "Automatic Sample Submission has been enabled on the local machine." -ForegroundColor Green
                } else {
                    Write-Host "Automatic Sample Submission is already enabled on the local machine." -ForegroundColor Green
                }
            } catch {
                Write-Host "Error on local machine: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    
        # Remote machines
        $remoteMachines = $RemoteComputers | Where-Object { $_ -ne "localhost" }
        if ($remoteMachines.Count -gt 0) {
            foreach ($computer in $remoteMachines) {
                Write-Host "Checking and enabling Automatic Sample Submission on $computer..." -ForegroundColor Yellow
                try {
                    # Test connection to the remote machine
                    Test-Connection -ComputerName $computer -Count 1 -Quiet -ErrorAction Stop | Out-Null
    
                    # Create a remote session with Basic Authentication
                    $session = New-PSSession -ComputerName $computer -Credential $Credential -Authentication Basic -ErrorAction Stop
                    $currentSetting = Invoke-Command -Session $session -ScriptBlock { (Get-MpPreference).SubmitSamplesConsent }
                    if ($currentSetting -ne 1) {
                        Invoke-Command -Session $session -ScriptBlock { Set-MpPreference -SubmitSamplesConsent 1 }
                        Write-Host "Automatic Sample Submission has been enabled on $computer." -ForegroundColor Green
                    } else {
                        Write-Host "Automatic Sample Submission is already enabled on $computer." -ForegroundColor Green
                    }
                    Remove-PSSession -Session $session
                } catch {
                    Write-Host "Error on $computer: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    }
    
    # Main script logic
    do {
        # Prompt for machine names
        $machinesInput = Read-Host "Enter machine names or IP addresses (comma-separated). Type 'localhost' for local machine"
        $machinesArray = $machinesInput -split "," | ForEach-Object { $_.Trim() }
    
        if ($machinesArray.Count -eq 0) {
            Write-Host "You must provide at least one machine. Please try again."
        }
    } while ($machinesArray.Count -eq 0)
    
    # Determine if localhost is included
    if ($machinesArray -contains "localhost") {
        # Perform tasks on local machine
        Enable-AutomaticSampleSubmission -RemoteComputers @("localhost")
    }
    
    # Handle remote machines
    $remoteMachines = $machinesArray | Where-Object { $_ -ne "localhost" }
    if ($remoteMachines.Count -gt 0) {
        $credential = Get-Credential -Message "Enter credentials for the remote machines"
        Enable-AutomaticSampleSubmission -RemoteComputers $remoteMachines -Credential $credential
    }
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
5. Disable Automatic Sample Submission on a local machine
   ![image](https://github.com/user-attachments/assets/ed5b1656-ab83-4d49-888b-65bd7cc08819)
7. Open PowerShell with admin privileges and run the `autosamplesubmission.ps1` script
8. Disable Automatic Sample Submission on a target remote machine
9. Run the PowerShell script and choose the second option. Enter the target machine's IP address to enable Automatic Sample Submission
   
