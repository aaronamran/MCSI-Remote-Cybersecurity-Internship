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
1. Save the following PowerShell script as `check-admins.ps1` in a Windows 7 VM
   ```
   # Function to check local administrators on a specified machine
   function Get-LocalAdministrators {
       param (
           [string]$ComputerName
       )
   
       try {
           # Run net localgroup Administrators command to retrieve local admins
           if ($ComputerName -eq $env:COMPUTERNAME) {
               $admins = net localgroup Administrators
           } else {
               $admins = Invoke-Command -ComputerName $ComputerName -ScriptBlock { net localgroup Administrators }
           }
   
           # Parse the output to get the list of admin accounts
           $adminList = ($admins -split "`n")[6..($admins.Length - 3)] | ForEach-Object { $_.Trim() }
   
           # Count the administrators
           $adminCount = $adminList.Count
   
           # Display results
           if ($adminCount -gt 1) {
               Write-Output "ALERT: $ComputerName has $adminCount local administrator accounts!"
               $adminList | ForEach-Object { Write-Output "- $_" }
           } else {
               Write-Output "$ComputerName has only one local administrator account."
           }
       }
       catch {
           Write-Output "Error: Unable to connect to $ComputerName."
       }
   }
   
   # Main Script Logic
   Write-Output "Choose an option:"
   Write-Output "1. Check local machine for multiple local administrator accounts"
   Write-Output "2. Check remote machines for multiple local administrator accounts"
   $choice = Read-Host "Enter your choice (1 or 2)"
   
   switch ($choice) {
       "1" {
           # Option 1: Local Machine Check
           Write-Output "Checking local machine for multiple administrator accounts..."
           Get-LocalAdministrators -ComputerName $env:COMPUTERNAME
       }
       "2" {
           # Option 2: Remote Machines Check
           $remoteMachines = Read-Host "Enter remote machine names or IP addresses separated by commas"
           $remoteMachineList = $remoteMachines -split ',' | ForEach-Object { $_.Trim() }
   
           foreach ($remoteMachine in $remoteMachineList) {
               Write-Output "Checking $remoteMachine for multiple administrator accounts..."
               Get-LocalAdministrators -ComputerName $remoteMachine
           }
       }
       default {
           Write-Output "Invalid input. Please enter 1 or 2."
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
4. To create a temporary nested group that has admin privileges and contains members, run each of the following commands on the local machine
   ```
   net localgroup TestGroup1 /add
   net localgroup Administrators "TestGroup1" /add
   net localgroup TestGroup2 /add
   net localgroup Administrators "TestGroup2" /add
   ```
   Note that the limitation on Windows 7 (and other non-domain, standalone Windows machines) is that local groups can contain users but cannot contain other local groups (subgroups). The `Administrators` group can contain other local groups, like `TestGroup1`, because it's a standard, built-in group that can hold both users and groups. However, a local group like TestGroup cannot contain another local group like `TestSub-group` directly. Only users can be added to `TestGroup1`, not other local groups.
5. To create temporary admin accounts that are members of `TestGroup1` and `TestGroup2`, run the commands below
   ```
   net user tempadmin1 pw123 /add
   net localgroup TestGroup1 tempadmin1 /add
   net user tempadmin2 pw123 /add
   net localgroup TestGroup2 tempadmin2 /add
   ```
6. Run the script on a local machine and demonstrate it detects mulitple local administrator accounts and nested group members
   ![image](https://github.com/user-attachments/assets/b532aad1-db0f-4838-97ec-062af04efc59)
7. Repeat steps 4 and 5 on a remote machine
8. Create multiple local administrator accounts on a remote machine
   ```
   net user tempadmin3 pw123 /add
   net user tempadmin4 pw123 /add
   net localgroup Administrators tempadmin3 /add
   net localgroup Administrators tempadmi4 /add
   ```
9. Run the script against the remote machine and validate its ability to detect multiple local administrator accounts and nested group members
   <br/>
   ![image](https://github.com/user-attachments/assets/96496877-e39d-427a-bccf-7179e8af2436)
   <br/>
   ![image](https://github.com/user-attachments/assets/be31ce80-5bd9-43f0-8f69-5c6ba97fa034)
10. Open command prompt with admin privileges and delete the temporary groups and admin accounts after task completion
   ```
   net user tempadmin1 /delete
   net user tempadmin2 /delete
   net user tempadmin3 /delete
   net user tempadmin4 /delete
   net localgroup TestGroup1 /delete
   net localgroup TestGroup2 /delete
   ```
   
