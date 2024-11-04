# Write A PS Script That Edits The Registry To Mark LSASS.exe As A Protected Process
In Windows Vista and later, processes running in Protected Mode are isolated from the system and other processes, reducing the risk of malware causing harm or accessing unauthorized data. The `lsass.exe` process handles security tasks like authentication and authorization in the Windows OS.

## References
- [LSASS - Local Security Authority Subsystem Service](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service) by Wikipedia
- [Configure added LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) by Microsoft
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) by gentilkiwi
- [Do You Really Know About LSA Protection (RunAsPPL)?](https://itm4n.github.io/lsass-runasppl/) by itm4n


## Tasks
- Identify the relevant registry key and value that needs to be modified to enable LSA protection for LSASS.exe
- Use PowerShell commands to edit the registry key and set the appropriate value to enable LSA protection
- Display a message indicating that LSA protection has been enabled for LSASS.exe
- Add parameters to the script that allow specifying remote machine names or IP addresses
- Display messages for each remote machine to indicate when LSA protection is already enabled or has been enabled by your script


## Recommended Approach
- Disable LSA protection on a local machine
- Run the script and demonstrate that it correctly detects and enables LSA protection on the local machine
- Demonstrate that Mimikatz cannot successfully dump cached password hashes from memory for the protected LSASS.exe process
- Disable LSA protection on a remote machine
- Run the script and demonstrate that it correctly detects and enables LSA protection on the remote machine


## Solutions With Scripts
1. The registry key to mark LSASS is `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`. The value that needs to be added is `RunAsPPL` (DWORD) set to `1` to enable the protection, and set to `0` to disable it
2. PowerShell script
   ```
   # PowerShell Script to Enable LSA Protection for lsass.exe
   # Compatible with Windows Vista and later
   
   # Constants
   $lsaKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
   $lsaValueName = "RunAsPPL"
   $enabledValue = 1
   
   # Function to enable LSA protection on the local machine
   function Enable-LsaProtectionLocal {
       # Check if LSA protection is already enabled
       if ((Get-ItemProperty -Path $lsaKeyPath -Name $lsaValueName -ErrorAction SilentlyContinue).$lsaValueName -eq $enabledValue) {
           Write-Output "LSA protection is already enabled on the local machine."
       } else {
           # Enable LSA protection
           Set-ItemProperty -Path $lsaKeyPath -Name $lsaValueName -Value $enabledValue
           Write-Output "LSA protection has been enabled for lsass.exe on the local machine."
       }
   }
   
   # Function to enable LSA protection on a remote machine
   function Enable-LsaProtectionRemote {
       param (
           [string]$remoteComputer
       )
   
       # Check if the remote machine is accessible
       if (Test-Connection -ComputerName $remoteComputer -Count 1 -Quiet) {
           try {
               # Check if LSA protection is already enabled on the remote machine
               $remoteValue = Invoke-Command -ComputerName $remoteComputer -ScriptBlock {
                   param ($lsaKeyPath, $lsaValueName)
                   (Get-ItemProperty -Path $lsaKeyPath -Name $lsaValueName -ErrorAction SilentlyContinue).$lsaValueName
               } -ArgumentList $lsaKeyPath, $lsaValueName
   
               if ($remoteValue -eq $enabledValue) {
                   Write-Output "LSA protection is already enabled on $remoteComputer."
               } else {
                   # Enable LSA protection on the remote machine
                   Invoke-Command -ComputerName $remoteComputer -ScriptBlock {
                       param ($lsaKeyPath, $lsaValueName, $enabledValue)
                       Set-ItemProperty -Path $lsaKeyPath -Name $lsaValueName -Value $enabledValue
                   } -ArgumentList $lsaKeyPath, $lsaValueName, $enabledValue
   
                   Write-Output "LSA protection has been enabled for lsass.exe on $remoteComputer."
               }
           } catch {
               Write-Output "An error occurred while trying to enable LSA protection on $remoteComputer: $_"
           }
       } else {
           Write-Output "Cannot reach $remoteComputer. Please check the network connection or machine name."
       }
   }
   
   # Main script logic
   Write-Output "Choose an option:"
   Write-Output "1. Enable LSA protection on the local machine"
   Write-Output "2. Enable LSA protection on a remote machine"
   $choice = Read-Host "Enter your choice (1 or 2)"
   
   switch ($choice) {
       1 {
           Enable-LsaProtectionLocal
       }
       2 {
           $remoteComputer = Read-Host "Enter the name or IP address of the remote machine"
           Enable-LsaProtectionRemote -remoteComputer $remoteComputer
       }
       default {
           Write-Output "Invalid input. Please restart the script and choose 1 or 2."
       }
   }
   ```
3. To run the script locally to enable LSA protection on the local machine run the following command in PowerShell
   ```
   .\Enable-LsaProtection.ps1
   ```
4. To run the script remotely on a list of remote machines, first enable PowerShell remoting
   ```
   Enable-PSRemoting -Force
   ```
   Windows 7 requires extra configurations to trust remote connections. Open PowerShell as Administrator and run the following command on both VMs to allow incoming WinRM traffic on all profiles
   ```
   Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP-PUBLIC' -RemoteAddress Any -Action Allow
   ```
   If both Windows VMs are not in the same domain, trusted hosts need to be configured on both VMs to allow remote connections
   ```
   Set-Item WSMan:\localhost\Client\TrustedHosts -Value "the_other_Windows_IP_Address"
   ```
   To test the remote connection from Windows 10 to Windows 7, run the command
   ```
   Enter-PSSession -ComputerName Windows7_IP_Address -Credential (Get-Credential)
   ```
   The script to enable LSA can be run using the following sample command
   ```
   .\Enable-LsaProtection.ps1 -ComputerNames "Server1", "192.168.1.50", "Server3"
   ```
5. Once LSA protection is enabled, try dumping cached credentials with Mimikatz. Run Mimikatz as admin, and the following commands
   ```
   privilege::debug
   sekurlsa::logonpasswords
   ```
6. Since LSASS is now protected, the password hashes should not be accessible. Mimikatz will either fail to retrieve the hashes or throw errors like `ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000005)` or `ERROR kuhl_m_sekurlsa_acquireLSA ; LSA process is protected`.

