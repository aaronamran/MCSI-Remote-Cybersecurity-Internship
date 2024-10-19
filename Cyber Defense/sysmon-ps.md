# Write A PS Script That Copies Sysmon To Remote Machines And Installs It With A Given Configuration File
Windows Sysmon logs system activity, including processes, network connections, and file access, helping detect malware and malicious activity. The Sysmon configuration file defines what events are logged, making it useful for monitoring, troubleshooting, and investigating security incidents

## References
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Sysmon Events](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events)
- [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
- [Autorunsc Usage](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns#autorunsc-usage)

## Tasks
- Create a PowerShell script that copies Sysmon to remote machines and install it
- Use a specified configuration file that captures the following events:
  - Unauthorized READ/WRITE access to lsass.exe
  - Processes command line execution arguments
  - Drivers that are loaded
  - DLLs that processes load
- Show the captured endpoint logs on the remote machines, confirming that the specified events are logged appropriately

## Benchmarks
- Copies Sysmon to remote machines and installs it with the provided configuration file
- Verifies that the configuration file correctly captures the required events mentioned in the specifications

## Solutions With Scripts
1. 
