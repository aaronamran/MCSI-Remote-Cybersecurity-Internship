# Write A PS Script That Copies Sysmon To Remote Machines And Installs It With A Given Configuration File
Windows Sysmon logs system activity, including processes, network connections, and file access, helping detect malware and malicious activity. The Sysmon configuration file defines what events are logged, making it useful for monitoring, troubleshooting, and investigating security incidents

## References
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) by Microsoft
- [Sysmon Events](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events) by Microsoft
- [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) by Microsoft
- [Autorunsc Usage](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns#autorunsc-usage) by Microsoft
- [sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) by SwiftOnSecurity on GitHub
- [Sysmon: How To Setup, Configure, and Analyze the System Monitor’s Events](https://syedhasan010.medium.com/sysmon-how-to-setup-configure-and-analyze-the-system-monitors-events-930e9add78d) by syed Hasan on Medium
- [How To Easily Analyze Your Sysmon Logs](https://www.gigasheet.com/post/how-to-easily-analyze-your-sysmon-logs#:~:text=Start%20making%20some%20noise%20on,That's%20it.) by Syed Hasan on gigasheet
- [Powershell: Remote install software](https://powershellexplained.com/2017-04-22-Powershell-installing-remote-software/) by Kevin Marquette on PowerShell Explained
- [Installation Error of Sysmon on Windows 7 VM - Sysmondrv Driver and StartService Issue](https://superuser.com/questions/1482486/installation-error-of-sysmon-on-windows-7-vm-sysmondrv-driver-and-startservice) by superuser
- [Security Update for Windows 7 for x64-based Systems (KB3033929)](https://www.microsoft.com/en-us/download/details.aspx?id=46148)


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
1. PowerShell script that copies Sysmon to the remote Windows machine, installs Sysmon with a given configuration file and verifies if Sysmon is running and logs the specified events (Delete credentials where necessary)
    ```
    # Parameters
    param
    (
      [Parameter(Mandatory=$true)] [string] $remoteMachine = $null
    )
      
    # Variables
    # $remoteMachine = "192.168.1.10"   # Replace with the IP or hostname of the remote Windows VM
    $sysmonExecutable = "C:\Sysmon\Sysmon64.exe"   # Local path to Sysmon executable
    $configFile = "C:\Sysmon\sysmon-config.xml"   # Local path to the Sysmon configuration file
    $remoteSharePath = "\\$remoteMachine\Sysmon"  # Use the existing shared folder path
    
    # Step 1: Copy Sysmon executable and configuration file to the shared folder
    Write-Host "-> Copying Sysmon executable and configuration file to the shared folder"
    Copy-Item -Path $sysmonExecutable -Destination $remoteSharePath
    Copy-Item -Path $configFile -Destination $remoteSharePath
    
    # Step 2: Install Sysmon on the remote machine
    Write-Host "-> Installing Sysmon on the remote machine"
    # Uninstall Sysmon first if it already exists on remote machine
    Invoke-Command -ScriptBlock { param($installer) cmd.exe /C "C:\$installer -u force 2>&1" | Out-Null } -Session $remote_session -ArgumentList $sysmonExecutable.split('\')[-1]

    # Installs a new Sysmon copied to the remote machine
    Invoke-Command -ScriptBlock { param($installer, $config) cmd.exe /C "C:\$installer -i C:\$config -accepteula 2>&1" } -Session $remote_session -ArgumentList $sysmonExecutable.split('\')[-1], $configFile.split('\')[-1]

    Write-Host "-> Installation complete"
    ```

    filler text
   ```
     # Step 3: Verify Sysmon installation
    Invoke-Command -ComputerName $remoteMachine -ScriptBlock {
        # Check if Sysmon is running
        if (Get-Process -Name sysmon -ErrorAction SilentlyContinue) {
            Write-Host "Sysmon is running."
        } else {
            Write-Host "Sysmon is not running."
        }
        # Check recent Sysmon events
        Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
    }
    
    # Step 4: Validate configuration
    Invoke-Command -ComputerName $remoteMachine -ScriptBlock {
        $configPath = "C:\Sysmon\sysmon-config.xml"
        if (Test-Path $configPath) {
            Write-Host "Sysmon configuration file exists on the remote machine."
        } else {
            Write-Host "Sysmon configuration file is missing!"
        }
    }
   ```
3. XML configuration file that captures unauthorised READ/WRITE access to lsass.exe, process command line execution arguments, drivers that are loaded and DLL that processes load
   ```
   <Sysmon schemaversion="4.60">
     <!-- Capture all hashes -->
     <HashAlgorithms>*</HashAlgorithms>
     <EventFiltering>
   
       <!-- Log unauthorized read/write access to lsass.exe -->
       <ProcessAccess onmatch="include">
        <TargetImage condition="image">lsass.exe</TargetImage>
       </ProcessAccess>
  
       <!-- Capture command line arguments -->
       <ProcessCreate onmatch="include">
        <CommandLine condition="contains">*</CommandLine>
       </ProcessCreate>
  
       <!-- Log drivers loaded -->
       <DriverLoad onmatch="include">
       </DriverLoad>
  
       <!-- Log DLLs loaded -->
       <ImageLoad onmatch="include">
        <ImageLoaded condition="end with">.dll</ImageLoaded>
       </ImageLoad>
  
     </EventFiltering>
   </Sysmon>
   ```
5. In target Windows 7 VM, open PowerShell with admin privileges, and confirm the IP address with `ipconfig`. Enter `winrm quickconfig` and choose yes. To enable PowerShell remoting, enter `Enable-PSRemoting` and either choose yes or yes to all. To check the listener status, enter `winrm enumerate winrm/config/listener`
6. On the sender Windows 7 VM, to add the target Windows 7 VM to the TrustedHosts list, use
   ```
   Set-Item WSMan:\localhost\Client\TrustedHosts -Value "<target_IP_address>"
   ```
   Or to simply allow connections to any IP address, replace the target IP address with an asterisk (*)
7. To test the PowerShell remote access from the sender VM, use the following commands
   ```
   Enter-PSSession -ComputerName <target_IP_address> -Credential (Get-Credential)
   ```
   Upon successful remote access, the PowerShell would look like this
   ![image](https://github.com/user-attachments/assets/2745445e-1719-4e77-87b0-0dc5af2afcaf)
8. In Windows 7 VM, Sysmon and its XML configuration file has to be placed in the `C:\Windows` directory. This can be confirmed when checking properties of Sysmon in Windows Services
9. 
