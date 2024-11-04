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
1. Save the PowerShell script below as 'autoSampleSubmission.ps1'
    ```
    # Enable Automatic Sample Submission on Windows Defender

    function Enable-AutomaticSampleSubmission {
        param (
            [string[]]$RemoteComputers = @()
        )
    
        if ($RemoteComputers.Count -eq 0) {
            # Local machine
            Write-Host "Checking and enabling Automatic Sample Submission on the local machine..."
            try {
                $currentSetting = (Get-MpPreference).SubmitSamplesConsent
                if ($currentSetting -ne 1) {
                    Set-MpPreference -SubmitSamplesConsent 1
                    Write-Host "Automatic Sample Submission has been enabled on the local machine."
                } else {
                    Write-Host "Automatic Sample Submission is already enabled on the local machine."
                }
            } catch {
                Write-Host "Error: $($_.Exception.Message)"
            }
        } else {
            # Remote machines
            foreach ($computer in $RemoteComputers) {
                Write-Host "Checking and enabling Automatic Sample Submission on $computer..."
                try {
                    $session = New-PSSession -ComputerName $computer -ErrorAction Stop
                    $currentSetting = Invoke-Command -Session $session -ScriptBlock { (Get-MpPreference).SubmitSamplesConsent }
                    if ($currentSetting -ne 1) {
                        Invoke-Command -Session $session -ScriptBlock { Set-MpPreference -SubmitSamplesConsent 1 }
                        Write-Host "Automatic Sample Submission has been enabled on $computer."
                    } else {
                        Write-Host "Automatic Sample Submission is already enabled on $computer."
                    }
                    Remove-PSSession -Session $session
                } catch {
                    Write-Host "Error on $computer: $($_.Exception.Message)"
                }
            }
        }
    }
    
    # Main script logic
    Write-Host "Choose an option:"
    Write-Host "1. Enable Automatic Sample Submission on local machine"
    Write-Host "2. Enable Automatic Sample Submission on remote machines"
    $choice = Read-Host "Enter your choice (1 or 2)"
    
    switch ($choice) {
        1 {
            Enable-AutomaticSampleSubmission
        }
        2 {
            $remoteMachines = Read-Host "Enter remote machine names or IP addresses separated by commas"
            $remoteComputersArray = $remoteMachines -split ","
            Enable-AutomaticSampleSubmission -RemoteComputers $remoteComputersArray
        }
        default {
            Write-Host "Invalid option. Please run the script again and enter either 1 or 2."
        }
    }
    ```
2. 
