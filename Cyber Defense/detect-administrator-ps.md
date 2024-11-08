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
   # Function to check local administrators on a specified machine
   function Get-LocalAdministrators {
       param (
           [string]$ComputerName
       )
       try {
           # Get all members of the 'Administrators' group, including nested groups
           $admins = Get-WmiObject -Class Win32_GroupUser -ComputerName $ComputerName |
               Where-Object { $_.GroupComponent -like '*"Administrators"' } |
               ForEach-Object { 
                   [ADSI]::New($_.PartComponent) | 
                   Select-Object -ExpandProperty Name 
               }
   
           # Get unique list of administrator accounts
           $uniqueAdmins = $admins | Sort-Object -Unique
   
           # Count the administrators
           $adminCount = $uniqueAdmins.Count
   
           # Display results
           if ($adminCount -gt 1) {
               Write-Host "ALERT: $ComputerName has $adminCount local administrator accounts!"
               $uniqueAdmins | ForEach-Object { Write-Host "- $_" }
           } else {
               Write-Host "$ComputerName has only one local administrator account."
           }
       }
       catch {
           Write-Host "Error: Unable to connect to $ComputerName."
       }
   }
   
   # Main Script Logic
   Write-Host "Choose an option:"
   Write-Host "1. Check local machine for multiple local administrator accounts"
   Write-Host "2. Check remote machines for multiple local administrator accounts"
   $choice = Read-Host "Enter your choice (1 or 2)"
   
   switch ($choice) {
       "1" {
           # Option 1: Local Machine Check
           Write-Host "Checking local machine for multiple administrator accounts..."
           Get-LocalAdministrators -ComputerName $env:COMPUTERNAME
       }
       "2" {
           # Option 2: Remote Machines Check
           $remoteMachines = Read-Host "Enter remote machine names or IP addresses separated by commas"
           $remoteMachineList = $remoteMachines -split ',' | ForEach-Object { $_.Trim() }
   
           foreach ($remoteMachine in $remoteMachineList) {
               Write-Host "Checking $remoteMachine for multiple administrator accounts..."
               Get-LocalAdministrators -ComputerName $remoteMachine
           }
       }
       default {
           Write-Host "Invalid input. Please enter 1 or 2."
       }
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
4. Run the script on a local machine and demonstrate it detects mulitple local administrator accounts and nested group members
5. Create multiple local administrator accounts on a remote machine
   ```
   net user tempadmin1 pw123 /add
   net user tempadmin2 pw123 /add
   net localgroup Administrators tempadmin1 /add
   net localgroup Administrators tempadmin2 /add
   ```
6. Run the script against the remote machine and validate its ability to detect multiple local administrator accounts and nested group members

   
