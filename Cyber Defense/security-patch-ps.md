# Write A PS Script To List Missing Security Patches
Keeping your software up to date is crucial for security. Security patches fix known vulnerabilities, and if they're not installed, attackers can exploit these weaknesses to access your system. To stay protected, ensure all applications have the latest security patches.


## Tasks
- Write a PowerShell script that can identify missing security patches on a local Windows machine
- Include the necessary PowerShell cmdlets to query Windows Update or the Windows Update Agent for patch information
- Extend the script to allow remote scanning of Windows machines for missing security patches
- Provide options to input remote machine names or IP addresses for scanning
- Implement a feature in the script to list the security hotfixes and patches already installed on the target machine
- Display the installed patches in an organized and user-friendly manner
- Provide informative output messages that display the missing security patches, if any, on the target machine
- Include details such as the KB number, patch description, and severity level


## Benchmarks
- Run the script locally and demonstrate that it correctly identifies installed and\or missing patches
- Run the script against a remote machine and demonstrate that it correctly identifies installed and\or missing patches


## Solutions With Scripts
1. Save the following PowerShell script as `check-missingpatches.ps1`
```
# Function to check for missing updates on a local machine
function Get-MissingUpdates {
    Write-Host "Checking for missing security updates on the local machine..." -ForegroundColor Yellow
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")

    if ($searchResult.Updates.Count -eq 0) {
        Write-Host "No missing security updates found." -ForegroundColor Green
    } else {
        Write-Host "Missing security patches:" -ForegroundColor Red
        foreach ($update in $searchResult.Updates) {
            [PSCustomObject]@{
                KBNumber    = $update.KBArticleIDs
                Title       = $update.Title
                Description = $update.Description
                Severity    = $update.MsrcSeverity
            } | Format-Table -AutoSize
        }
    }
}

# Function to check installed updates on a local machine
function Get-InstalledUpdates {
    Write-Host "Listing installed security patches on the local machine..." -ForegroundColor Yellow
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $searchResult = $updateSearcher.Search("IsInstalled=1 and Type='Software' and IsHidden=0")

    if ($searchResult.Updates.Count -eq 0) {
        Write-Host "No installed security updates found." -ForegroundColor Red
    } else {
        Write-Host "Installed security patches:" -ForegroundColor Green
        foreach ($update in $searchResult.Updates) {
            [PSCustomObject]@{
                KBNumber    = $update.KBArticleIDs
                Title       = $update.Title
                Description = $update.Description
                Severity    = $update.MsrcSeverity
            } | Format-Table -AutoSize
        }
    }
}

# Function to scan remote machines for missing updates
function Get-RemoteMissingUpdates {
    param (
        [string]$ComputerName
    )

    Write-Host "Checking for missing security updates on remote machine: $ComputerName..." -ForegroundColor Yellow
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")

        if ($searchResult.Updates.Count -eq 0) {
            Write-Host "No missing security updates found on $env:COMPUTERNAME." -ForegroundColor Green
        } else {
            Write-Host "Missing security patches on $env:COMPUTERNAME:" -ForegroundColor Red
            foreach ($update in $searchResult.Updates) {
                [PSCustomObject]@{
                    KBNumber    = $update.KBArticleIDs
                    Title       = $update.Title
                    Description = $update.Description
                    Severity    = $update.MsrcSeverity
                } | Format-Table -AutoSize
            }
        }
    }
}

# Function to scan remote machines for installed updates
function Get-RemoteInstalledUpdates {
    param (
        [string]$ComputerName
    )

    Write-Host "Listing installed security patches on remote machine: $ComputerName..." -ForegroundColor Yellow
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=1 and Type='Software' and IsHidden=0")

        if ($searchResult.Updates.Count -eq 0) {
            Write-Host "No installed security updates found on $env:COMPUTERNAME." -ForegroundColor Red
        } else {
            Write-Host "Installed security patches on $env:COMPUTERNAME:" -ForegroundColor Green
            foreach ($update in $searchResult.Updates) {
                [PSCustomObject]@{
                    KBNumber    = $update.KBArticleIDs
                    Title       = $update.Title
                    Description = $update.Description
                    Severity    = $update.MsrcSeverity
                } | Format-Table -AutoSize
            }
        }
    }
}

# Main menu for local or remote machine scan
$choice = Read-Host "Do you want to scan a [L]ocal or [R]emote machine for missing patches? (L/R)"
if ($choice -eq 'L') {
    Get-MissingUpdates
    Get-InstalledUpdates
} elseif ($choice -eq 'R') {
    $remoteComputer = Read-Host "Enter the remote machine's name or IP address"
    Get-RemoteMissingUpdates -ComputerName $remoteComputer
    Get-RemoteInstalledUpdates -ComputerName $remoteComputer
} else {
    Write-Host "Invalid choice, please run the script again and select either 'L' or 'R'." -ForegroundColor Red
}
```
2. Set Execution Policy (if necessary): If you encounter a script execution error, use the following command to allow the script to run:
   ```
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
3. To enable PowerShell remoting between local and target VMs, get the IP address of the target remote machine. Then set it as a trusted host on the local machine to allow remote connections
   ```
   Set-Item WSMan:\localhost\Client\TrustedHosts -Value "the_other_Windows_IP_Address"
   winrm quickconfig -Force
   Enable-PSRemoting -Force
   ```
4. Run the script locally and demonstrate that it correctly identifies installed and\or missing patches
5. Run the script against a remote machine and demonstrate that it correctly identifies installed and\or missing patches
