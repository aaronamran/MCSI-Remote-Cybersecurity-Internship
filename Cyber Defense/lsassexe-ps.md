# Write A PS Script That Edits The Registry To Mark LSASS.exe As A Protected Process
In Windows Vista and later, processes running in Protected Mode are isolated from the system and other processes, reducing the risk of malware causing harm or accessing unauthorized data. The `lsass.exe` process handles security tasks like authentication and authorization in the Windows OS.

## References
- LSASS - [Local Security Authority Subsystem Service (https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)
- [Configure added LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) by Microsoft
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) by gentilkiwi


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
1. The registry key to mark LSASS is `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`. The value that needs to be added is `RunAsPPL` (DWORD) set to `1` to enable the protection
2. PowerShell script
   ```
   # Function to enable LSA protection for LSASS
   function Enable-LsaProtection {
       param (
           [string]$ComputerName
       )
    
       # Registry path and value to enable LSA protection
       $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
       $regValueName = "RunAsPPL"
        
       # Check if the LSA protection is already enabled
       try {
           $lsaProtection = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction Stop -ComputerName $ComputerName
           if ($lsaProtection.$regValueName -eq 1) {
              Write-Host "LSA protection is already enabled on $ComputerName."
           } else {
               Set-ItemProperty -Path $regPath -Name $regValueName -Value 1 -ComputerName $ComputerName
               Write-Host "LSA protection enabled on $ComputerName."
           }
       } catch {
           Write-Host "Enabling LSA protection on $ComputerName..."
           New-ItemProperty -Path $regPath -Name $regValueName -Value 1 -PropertyType DWORD -Force -ComputerName $ComputerName
           Write-Host "LSA protection successfully enabled on $ComputerName."
       }
   }
   
   # Main script to run on local or multiple remote machines
   param (
       [string[]]$ComputerNames = @("localhost")  # Default to localhost, or provide a list of remote machines
   )
   
   foreach ($ComputerName in $ComputerNames) {
       Write-Host "Processing $ComputerName..."
       Enable-LsaProtection -ComputerName $ComputerName
   }
   
   Write-Host "LSA protection task completed."
   ```
3. To run the script locally to enable LSA protection on the local machine run the following command in PowerShell
   ```
   .\Enable-LsaProtection.ps1
   ```
4. To run the script remotely on a list of remote machines, run the following sample command
   ```
   .\Enable-LsaProtection.ps1 -ComputerNames "Server1", "192.168.1.50", "Server3"
   ```
5. Once LSA protection is enabled, try dumping cached credentials with Mimikatz
