# Write A PS Script That Detects Installed Anti-Virus Software
Detecting installed antivirus software on Windows is essential for security professionals to assess system protection against threats. A PowerShell script can retrieve information about installed antivirus, providing insights into an organization's security posture.

## References
- [How to get Antivirus information with WMI (VBScript)](https://learn.microsoft.com/en-us/archive/blogs/alejacma/how-to-get-antivirus-information-with-wmi-vbscript) by Microsoft

## Tasks
- Write a PowerShell script that retrieves information about installed anti-virus software on a local Windows machine
- Enhance the script to include the option of executing it on a remote Windows machine
- Utilize WMI or PowerShell cmdlets (e.g., Get-WmiObject, Get-CimInstance) to gather information about installed software
- Parse the information retrieved to identify the presence of anti-virus software
- Display the list of detected anti-virus software on the console
- Provide clear and descriptive output, including the name of the anti-virus software and its status (enabled or disabled)

## Benchmarks
- Ensure an anti-virus software is installed on your local machine
- Run the script on your local machine and demonstrate that it correctly detects the presence of the anti-virus software
- Ensure an anti-virus software is installed on a remote machine
- Run the script against the remote machine and demonstrate that it correctly detects the presence of anti-virus software
