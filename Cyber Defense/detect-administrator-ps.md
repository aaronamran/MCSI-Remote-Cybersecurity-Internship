# Write A PS Script That Detects Whether A Machine Has More Than 1 Local Administrator
Best practice is to have only one local administrator per machine. Multiple admin accounts increase the risk of malicious users gaining control, accessing sensitive data, or installing malware. If one admin account is compromised, others may also be at risk.



## Tasks
- Write a PowerShell script that enumerates all local user accounts on the machine
- If there is more than one user account with local administrator privileges, the script should raise an alert
- Extend the script to scan nested groups (sub-groups) that have been provided local administrator privileges
- Count the total number of local administrator accounts, including those in nested groups
- Implement a feature in the script to scan remote machines for local administrator accounts
- Allow the script to accept a list of remote machine names or IP addresses as input


## Recommended Approach
- Run the script on a local machine and demonstrate that it correctly detects multiple local administrator accounts and nested group members
- Create multiple local administrator accounts on a remote machine
- Run the script against the remote machine and validate its ability to detect multiple local administrator accounts and nested group members


## Solutions With Scripts
1. Save the following PowerShell script as `check-admins.ps1`
   ```
    # Function to get local administrators from a machine (local or remote)
    function Get-LocalAdministrators {
        param (
            [string]$ComputerName = $env:COMPUTERNAME
        )
    
        try {
            # Get the Administrators group
            $adminGroup = [ADSI]"WinNT://$ComputerName/Administrators,group"
            $adminMembers = @()
    
            # Enumerate group members
            foreach ($member in $adminGroup.Invoke("Members")) {
                $memberObj = [ADSI]$member
                $adminMembers += $memberObj.Name
            }
    
            # Return the list of members
            return $adminMembers
        } catch {
            Write-Host "Error retrieving administrators from $ComputerName: $_" -ForegroundColor Red
            return $null
        }
    }
    
    # Function to count admin accounts including nested groups
    function Count-LocalAdministrators {
        param (
            [string]$ComputerName = $env:COMPUTERNAME
        )
    
        $adminAccounts = Get-LocalAdministrators -ComputerName $ComputerName
    
        if ($adminAccounts) {
            Write-Host "Local Administrators on $ComputerName:" -ForegroundColor Cyan
            $adminAccounts | ForEach-Object { Write-Host $_ }
    
            # Check if more than one admin exists
            if ($adminAccounts.Count -gt 1) {
                Write-Host "ALERT: More than one local administrator detected on $ComputerName!" -ForegroundColor Yellow
            } else {
                Write-Host "OK: Only one local administrator found on $ComputerName." -ForegroundColor Green
            }
    
            # Return the count of local administrators
            return $adminAccounts.Count
        }
        return 0
    }
    
    # Function to check administrators on multiple remote machines
    function Check-RemoteAdministrators {
        param (
            [string[]]$ComputerList
        )
    
        foreach ($computer in $ComputerList) {
            Write-Host "`nScanning $computer for local administrators..." -ForegroundColor Blue
            Count-LocalAdministrators -ComputerName $computer
        }
    }
    
    # Main script
    $localAdminCount = Count-LocalAdministrators -ComputerName $env:COMPUTERNAME
    
    if ($localAdminCount -gt 1) {
        Write-Host "`nALERT: Multiple administrators on the local machine!" -ForegroundColor Yellow
    }
    
    # Input list of remote machines (either names or IP addresses)
    $remoteMachines = @("RemoteMachine1", "RemoteMachine2", "192.168.1.10")  # Modify this list
    
    Check-RemoteAdministrators -ComputerList $remoteMachines
   ```
2. 
   
