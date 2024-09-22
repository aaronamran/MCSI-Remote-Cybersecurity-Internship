# Write A PS Script That Enables The AlwaysInstallElevated Registry Key
The AlwaysInstallElevated vulnerability in Microsoft Windows lets unprivileged attackers install programs with elevated privileges without user consent, potentially enabling the installation of spyware and malware.

Powerup.ps1 is a PowerShell script that escalates privileges by adding users, changing passwords, and modifying permissions, allowing attackers to access sensitive data or systems.

## References
- [AlwaysInstallElevated](https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated) by Microsoft
- [PowerSploit / PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) by PowerShellMafia on GitHub

## Tasks
- Create a PowerShell script that modifies the Windows registry to enable the AlwaysInstallElevated registry key
- Execute the PowerShell script to enable the AlwaysInstallElevated registry key on the target system
- Exploit the AlwaysInstallElevated vulnerability using PowerUp.ps1

## 
