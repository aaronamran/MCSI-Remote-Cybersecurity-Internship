# PowerShell
PowerShell is a cross-platform (Windows, Linux, and macOS) automation and configuration tool/framework that works well with your existing tools and is optimized for dealing with structured data (e.g. JSON, CSV, XML, etc.), REST APIs, and object models.


## Write A PS Script That Installs An Insecure Windows Service
An insecure Windows service is one that can be easily exploited by a Penetration Tester. These services often lack proper security protections and can be compromised through vulnerabilities in the code or weak passwords.

#### Tasks
- Research how to set up a Windows service with insecure configurations, such as weak permissions or allowing modifications by EVERYONE
- Create a PowerShell script that automates the creation of the insecure Windows service, incorporating the vulnerable configurations identified in the research
- Execute your PowerShell script to install the insecure Windows service on the target system
- Use PowerUp.ps1 to exploit the insecure Windows service that your script installed

#### Recommended Approach
- Search the following keywords on Google: vulnerable windows service binpath
- Research how to modify the permissions of a Windows Service using SUBINACL.exe
- Research how to create a new Windows Service using sc.exe
- Create a vulnerable Windows Service that any user, regardless of their permission levels, can modify
- Use PowerUp.ps1 to exploit the vulnerable Windows Service and obtain unauthorised SYSTEM privileges on the machine


## Write A PS Script That Enables The AlwaysInstallElevated Registry Key
The AlwaysInstallElevated vulnerability in Microsoft Windows lets unprivileged attackers install programs with elevated privileges without user consent, potentially enabling the installation of spyware and malware.

Powerup.ps1 is a PowerShell script that escalates privileges by adding users, changing passwords, and modifying permissions, allowing attackers to access sensitive data or systems.


#### Tasks
- Create a PowerShell script that modifies the Windows registry to enable the AlwaysInstallElevated registry key
- Execute the PowerShell script to enable the AlwaysInstallElevated registry key on the target system
- Exploit the AlwaysInstallElevated vulnerability using PowerUp.ps1

#### 
