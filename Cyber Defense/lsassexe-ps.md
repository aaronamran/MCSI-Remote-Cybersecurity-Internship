# Write A PS Script That Edits The Registry To Mark LSASS.exe As A Protected Process
In Windows Vista and later, processes running in Protected Mode are isolated from the system and other processes, reducing the risk of malware causing harm or accessing unauthorized data. The `lsass.exe` process handles security tasks like authentication and authorization in the Windows OS.


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
