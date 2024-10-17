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

## Solutions With Scripts
1. The `AlwaysInstallElevated` registry key exists in two locations: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer` and `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer`
2. Save and run the following PowerShell script with administrator privileges to enable `AlwaysInstallElevated`
   ```
   # PowerShell script to enable the AlwaysInstallElevated registry key

   # Enable AlwaysInstallElevated for Local Machine
   $regPathLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer"
   Set-ItemProperty -Path $regPathLM -Name "AlwaysInstallElevated" -Value 1 -Force

   # Enable AlwaysInstallElevated for Current User
   $regPathCU = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer"
   Set-ItemProperty -Path $regPathCU -Name "AlwaysInstallElevated" -Value 1 -Force

   Write-Host "AlwaysInstallElevated has been enabled for both HKLM and HKCU."
   ```
3. To execute the script, open PowerShell with administrator privileges and navigate to the folder where the script is stored. Run the script using `./Enable-AlwaysInstallElevated.ps1`
4. To exploit the vulnerability with PowerUp.ps1, download PowerUp.ps1 from the PowerSploit repository. In the same PowerShell session, run the following command to import and execute PowerUp.ps1
   ```
   Import-Module .\PowerUp.ps1
   Invoke-AllChecks
   ```
5. (Optional) After completion of the tests, to disable AlwaysInstallElevated, set the registry keys back to 0
   ```
   # Disable AlwaysInstallElevated for Local Machine
   Set-ItemProperty -Path $regPathLM -Name "AlwaysInstallElevated" -Value 0 -Force
   
   # Disable AlwaysInstallElevated for Current User
   Set-ItemProperty -Path $regPathCU -Name "AlwaysInstallElevated" -Value 0 -Force
   ```



