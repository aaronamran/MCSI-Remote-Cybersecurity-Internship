# Write A PS Script To Turn On Windows Defender
Windows Defender, pre-installed on Windows 10, protects against malware and online threats. Its "Real-time Protection" feature continuously monitors for infections and suspends suspicious programs automatically.


## References
- [Manage Windows Defender using PowerShell](https://learn.microsoft.com/en-us/archive/technet-wiki/52251.manage-windows-defender-using-powershell) by Microsoft
- [Running Remote Commands](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/running-remote-commands?view=powershell-7.4&viewFallbackFrom=powershell-7) by Microsoft
  

## PowerShell Script Requirements
- Checks the current status of the Windows Defender on a local machine
- If Windows Defender is enabled, displays a message indicating that it is already enabled
- If Windows Defender is not enabled, proceeds to enable it
- Implements the logic to turn on the Windows Defender programmatically
- After enabling Windows Defender, includes the logic to force it to update itself
- Displays a success message once Windows Defender is enabled and updated
- Supports remote machines
- Accepts a list of remote machine names or IP addresses as input



## Recommended Approach
- Enable your Windows Defender
- Run the script on your local machine
- Disable your Windows Defender
- Run the script again on your local machine
- Start up two (2) Windows virtual machines
- Enable Windows Defender on 1 machine
- Disable Windows Defender on the other machine
- Create a list containing the remote machine addresses
- Scan/fix the remote hosts by passing the list to your tool


## Benchmarks
- Defender Enabled locally: The script running on your local machine correctly detects Windows Defender status as enabled
- Defender Disabled locally: The script running on your local machine enables Windows Defender and updates itself
- Ensure that real-time protection is enabled after turning on Windows Defender
- The remote hosts list scan detects Windows Defender enabled on one machine
- The remote hosts list scan enables Windows Defender on the vulnerable machine and updates itself


## Solutions With Scripts
1. 


