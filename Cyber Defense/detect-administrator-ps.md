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


## Practical Approach
1. Save the following PowerShell script as `check-admins.ps1` in a Windows 7 VM
   ```
   # Define function to check local administrator accounts on a machine
   function Check-LocalAdmin {
       param (
           [string]$MachineName
       )
   
       Write-Host "Checking local administrator accounts on $MachineName..."  # Debug line
   
       # Get local group memberships via WMI
       $adminsGroup = Get-WmiObject -Class Win32_Group -Filter "LocalAccount = TRUE AND Name = 'Administrators'" -ComputerName $MachineName
       $adminMembers = Get-WmiObject -Class Win32_GroupUser -ComputerName $MachineName | Where-Object { $_.GroupComponent -like "*$($adminsGroup.Name)*" }
   
       # Initialize an array to hold admin users and groups
       $adminUsersAndGroups = @()
   
       # Add users directly in the Administrators group
       foreach ($admin in $adminMembers) {
           $userName = $admin.PartComponent -replace '.*Domain="([^"]+)".*Name="([^"]+)".*', '$2'
   
           # Check if it's a user
           $userObject = Get-WmiObject -Class Win32_UserAccount -ComputerName $MachineName | Where-Object { $_.Name -eq $userName }
           
           if ($userObject) {
               # If it's a user, add to the list with (user)
               $adminUsersAndGroups += "$userName (user)"
           } else {
               # It's not a user, so it's likely a group (skip this item)
           }
       }
   
       # Now check for nested groups
       foreach ($admin in $adminMembers) {
           $groupName = $admin.PartComponent -replace '.*Domain="([^"]+)".*Name="([^"]+)".*', '$2'
   
           # Check if it's a group (skip processing nested groups if the group is not an actual user)
           $groupObject = Get-WmiObject -Class Win32_Group -ComputerName $MachineName | Where-Object { $_.Name -eq $groupName }
   
           if ($groupObject) {
               # Now list the users in the nested group
               Write-Host "Nested Group: $groupName"  # Optional debug line
               $nestedGroupMembers = Get-WmiObject -Class Win32_GroupUser -ComputerName $MachineName | Where-Object { $_.GroupComponent -like "*$groupName*" }
               foreach ($nestedMember in $nestedGroupMembers) {
                   $nestedUser = $nestedMember.PartComponent -replace '.*Domain="([^"]+)".*Name="([^"]+)".*', '$2'
                   # Filter out groups (we only want actual user accounts)
                   $nestedUserObject = Get-WmiObject -Class Win32_UserAccount -ComputerName $MachineName | Where-Object { $_.Name -eq $nestedUser }
                   if ($nestedUserObject) {
                       Write-Host "  Nested User: $nestedUser"  # Output the nested user
                       $adminUsersAndGroups += "$nestedUser (user)"
                   }
               }
           }
       }
   
       # Remove duplicates from the list
       $adminUsersAndGroups = $adminUsersAndGroups | Sort-Object -Unique
   
       # Count the total number of local administrator accounts
       $adminCount = $adminUsersAndGroups.Count
   
       # Alert if there is more than one local admin account
       if ($adminCount -gt 1) {
           Write-Warning "Alert: There are $adminCount local administrator accounts!"
       } else {
           Write-Host "There is $adminCount local administrator account."
       }
   
       # Display all the local admin users with machine name
       Write-Host "The Local Administrator Accounts on $MachineName are:"
       foreach ($adminUserOrGroup in $adminUsersAndGroups) {
           Write-Host "-> $adminUserOrGroup"  # Display each user with an arrow before it
       }
   }
   
   # Main script logic
   $choice = Read-Host "Choose 1 for local machine or 2 for remote machine (Invalid input will be rejected)"
   
   # Ensure valid input for machine type
   if ($choice -eq "1") {
       # Check local machine
       Check-LocalAdmin -MachineName $env:COMPUTERNAME
   } elseif ($choice -eq "2") {
       # Get list of remote machines (IP or hostnames)
       $remoteMachines = Read-Host "Enter a comma-separated list of remote machine names or IP addresses" 
       $remoteMachinesArray = $remoteMachines.Split(',')
   
       # Loop through the list of remote machines and check for local admins
       foreach ($machine in $remoteMachinesArray) {
           Write-Host "Checking local admins on $machine..."
           Check-LocalAdmin -MachineName $machine.Trim()
       }
   } else {
       Write-Host "Invalid choice. Please enter 1 for local or 2 for remote."
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
   Note that the limitation on Windows 7 (and other non-domain, standalone Windows machines) is that local groups can contain users but cannot contain other local groups (subgroups). The `Administrators` group can contain other local groups, like `TestGroup1`, because it's a standard, built-in group that can hold both users and groups. However, a local group like `TestGroup` cannot contain another local group like `TestSub-group` directly. Only users can be added to `TestGroup1`, not other local groups.
5. To create temporary admin accounts that are members of `TestGroup1` and `TestGroup2`, run the commands below
   ```
   net user tempadmin1 pw123 /add
   net localgroup TestGroup1 tempadmin1 /add
   net user tempadmin2 pw123 /add
   net localgroup TestGroup2 tempadmin2 /add
   ```
6. Run the script on a local machine and demonstrate it detects mulitple local administrator accounts and nested group members
   ![image](https://github.com/user-attachments/assets/6b641fc6-d76d-4a63-a767-623983576c80)
7. Repeat steps 4 and 5 on a remote machine
8. Create multiple local administrator accounts on a remote machine
   ```
   net user tempadmin3 pw123 /add
   net user tempadmin4 pw123 /add
   net localgroup Administrators tempadmin3 /add
   net localgroup Administrators tempadmi4 /add
   ```
9. Check for administrators on the remote machine
   ![image](https://github.com/user-attachments/assets/fc70eb9c-87bf-41c7-be4e-44ddb81a0c4b)
10. Run the script from the local machine against the remote machine and validate its ability to detect multiple local administrator accounts and nested group members <br/>
   ![image](https://github.com/user-attachments/assets/ed879cca-78eb-48ef-b499-7ebc3ca6a783)
11. Open command prompt with admin privileges and delete the temporary groups and admin accounts after task completion
   ```
   net user tempadmin1 /delete
   net user tempadmin2 /delete
   net user tempadmin3 /delete
   net user tempadmin4 /delete
   net localgroup TestGroup1 /delete
   net localgroup TestGroup2 /delete
   ```
   
