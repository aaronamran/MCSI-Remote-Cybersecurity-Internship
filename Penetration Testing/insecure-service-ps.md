# Write A PS Script That Installs An Insecure Windows Service
An insecure Windows service is one that can be easily exploited by a Penetration Tester. These services often lack proper security protections and can be compromised through vulnerabilities in the code or weak passwords.

## Tasks
- Research how to set up a Windows service with insecure configurations, such as weak permissions or allowing modifications by EVERYONE
- Create a PowerShell script that automates the creation of the insecure Windows service, incorporating the vulnerable configurations identified in the research
- Execute your PowerShell script to install the insecure Windows service on the target system
- Use PowerUp.ps1 to exploit the insecure Windows service that your script installed

## Recommended Approach
- Search the following keywords on Google: vulnerable windows service binpath
- Research how to modify the permissions of a Windows Service using SUBINACL.exe
- Research how to create a new Windows Service using sc.exe
- Create a vulnerable Windows Service that any user, regardless of their permission levels, can modify
- Use PowerUp.ps1 to exploit the vulnerable Windows Service and obtain unauthorised SYSTEM privileges on the machine

## PowerShell Scripts

#### Standard PowerShell Script
```
# Define parameters for the new Windows service
$serviceName = "InsecureService"
$displayName = "Insecure Test Service"
$binaryPath = "C:\Path\To\InsecureService.exe" # Path to the executable of the service

# Create the Windows service
New-Service -Name $serviceName -DisplayName $displayName -BinaryPath $binaryPath -StartupType Manual

# Set permissions to allow everyone to modify the service
$serviceAclPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$acl = Get-Acl $serviceAclPath

# Define a new rule allowing Everyone full control
$everyone = New-Object System.Security.AccessControl.SecurityIdentifier "S-1-1-0" # Everyone SID
$rule = New-Object System.Security.AccessControl.RegistryAccessRule($everyone, "FullControl", "Allow")

# Apply the new rule
$acl.SetAccessRule($rule)
Set-Acl -Path $serviceAclPath -AclObject $acl

# Output the result
Write-Host "Insecure Windows service '$serviceName' created with insecure permissions."
```

#### PowerShell v1.0 Compatible Script
```
# Define service parameters
$serviceName = "InsecureService"
$displayName = "Insecure Test Service"
$binaryPath = "C:\Path\To\InsecureService.exe" # Path to the executable of the service

# Create the Windows service
sc.exe create $serviceName binPath= $binaryPath DisplayName= $displayName start= demand

# Grant everyone permissions to modify the service using SUBINACL
# Ensure SUBINACL is installed and available in the PATH
$subinaclPath = "C:\Path\To\subinacl.exe" # Update with the correct path to SUBINACL
& $subinaclPath /service $serviceName /grant=everyone=f

# Output the result
Write-Host "Insecure Windows service '$serviceName' created with insecure permissions."
```

