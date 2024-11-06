# Write A PS Script That Copies Sysmon To Remote Machines And Installs It With A Given Configuration File
Windows Sysmon logs system activity, including processes, network connections, and file access, helping detect malware and malicious activity. The Sysmon configuration file defines what events are logged, making it useful for monitoring, troubleshooting, and investigating security incidents

## References
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) by Microsoft
- [Sysmon Events](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events) by Microsoft
- [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) by Microsoft
- [Autorunsc Usage](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns#autorunsc-usage) by Microsoft
- [Sysmon: When Visibility is Key](https://www.thedfirspot.com/post/sysmon-when-visibility-is-key) by The DFIR Spot
- [sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) by SwiftOnSecurity on GitHub
- [Sysmon: How To Setup, Configure, and Analyze the System Monitor’s Events](https://syedhasan010.medium.com/sysmon-how-to-setup-configure-and-analyze-the-system-monitors-events-930e9add78d) by syed Hasan on Medium
- [How to Tune Windows System Monitor (Sysmon)](https://www.whatsupgold.com/blog/how-to-tune-windows-system-monitor-sysmon) by Dan Franciscus on WhatsUp Gold
- [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide/tree/master) by trustedsec on GitHub
- [Process Access](https://github.com/trustedsec/SysmonCommunityGuide/blob/master/chapters/process-access.md) by trustedsec on GitHub
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
    param (
        [Parameter(Mandatory=$true)]
        [string] $remoteMachine
    )
    
    # Variables
    $sysmonExecutable = "C:\Sysmon\Sysmon64.exe"       # Local path to Sysmon executable
    $configFile = "C:\Sysmon\sysmon-config.xml"        # Local path to Sysmon configuration file
    $remoteWindowsPath = "\\$remoteMachine\C$\Windows" # Target directory for Sysmon on the remote machine
    
    # Step 1: Establish a remote session
    Write-Host "-> Establishing session with $remoteMachine"
    try {
        $remoteSession = New-PSSession -ComputerName $remoteMachine -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to $remoteMachine. Ensure the machine is reachable and PowerShell remoting is enabled."
        return
    }
    
    # Step 2: Copy Sysmon executable and configuration file to the C:\Windows directory on the remote machine
    Write-Host "-> Copying Sysmon executable and configuration file to the remote machine's C:\Windows directory"
    try {
        # Copy files to the remote machine's C:\Windows directory
        Copy-Item -Path $sysmonExecutable -Destination $remoteWindowsPath -Force
        Copy-Item -Path $configFile -Destination $remoteWindowsPath -Force
    } catch {
        Write-Host "Failed to copy files to $remoteMachine. Check permissions and network access."
        Remove-PSSession -Session $remoteSession
        return
    }
    
    # Step 3: Install or reinstall Sysmon on the remote machine
    Write-Host "-> Installing Sysmon on $remoteMachine"
    $sysmonExeName = [System.IO.Path]::GetFileName($sysmonExecutable)
    $configFileName = [System.IO.Path]::GetFileName($configFile)
    
    try {
        # Uninstall Sysmon if it exists
        Invoke-Command -Session $remoteSession -ScriptBlock {
            param($sysmonExe)
            if (Test-Path "C:\Windows\$sysmonExe") {
                Write-Host "Uninstalling existing Sysmon instance..."
                cmd.exe /C "C:\Windows\$sysmonExe -u force" | Out-Null
            }
        } -ArgumentList $sysmonExeName
    
        # Install Sysmon with the new configuration in C:\Windows
        Invoke-Command -Session $remoteSession -ScriptBlock {
            param($sysmonExe, $configFile)
            Write-Host "Installing Sysmon with new configuration..."
            cmd.exe /C "C:\Windows\$sysmonExe -i C:\Windows\$configFile -accepteula" | Out-Null
        } -ArgumentList $sysmonExeName, $configFileName
        Write-Host "-> Sysmon installation complete on $remoteMachine"
    } catch {
        Write-Host "Failed to install Sysmon on $remoteMachine. Please check permissions and system requirements."
    }
    
    # Step 4: Clean up
    Remove-PSSession -Session $remoteSession
    ```


2. XML configuration file that captures unauthorised READ/WRITE access to lsass.exe, process command line execution arguments, drivers that are loaded and DLL that processes load
   ```
   <Sysmon schemaversion="4.60">
     <!-- Capture all hashes -->
     <HashAlgorithms>*</HashAlgorithms>
     <EventFiltering>
   
       <!-- Log unauthorized read/write access to lsass.exe -->
       <ProcessAccess onmatch="include">
        <TargetImage condition="image">C:\Windows\system32\lsass.exe</TargetImage>
       </ProcessAccess>
  
       <!-- Capture command line arguments -->
       <ProcessCreate onmatch="include">
        <CommandLine condition="contains">*</CommandLine>
       </ProcessCreate>
  
       <!-- Log drivers loaded -->
       <DriverLoad onmatch="exclude">
       </DriverLoad>
  
       <!-- Log DLLs loaded -->
       <ImageLoad onmatch="include">
        <ImageLoaded condition="end with">.dll</ImageLoaded>
       </ImageLoad>
  
     </EventFiltering>
   </Sysmon>
   ```
5. To understand how Sysmon XML configuration files work, let's take a look below
   ```
    #Before change
    <RuleGroup name="" groupRelation="or">
      <ImageLoad onmatch="include">
       <!--NOTE: Using "include" with no rules means nothing in this section will be logged-->
      </ImageLoad>
     </RuleGroup>
    
    #After changes
    <RuleGroup name="" groupRelation="or">
      <ImageLoad onmatch="exclude">
       <!--NOTE: Using "include" with no rules means nothing in this section will be logged-->
      </ImageLoad>
     </RuleGroup>
    ```
    - Regarding the 'Before change':
      - `onmatch="include"`: When set to "include", Sysmon will log ImageLoad events that match any specified rules within this section
      - No Rules: Since there are no rules inside the <ImageLoad> section, no ImageLoad events are actually logged. The comment explains this by noting that "include" without any rules means nothing in this section is logged
    - Regarding the 'After change':
      - `onmatch="exclude"`: When set to "exclude", Sysmon will exclude ImageLoad events that match any specified rules inside this section
      - No Rules: With no rules present, all ImageLoad events are logged because nothing is excluded. By specifying "exclude" with no rules, the configuration effectively enables logging for every ImageLoad event
6. In target Windows 7 VM, open PowerShell with admin privileges, and confirm the IP address with `ipconfig`. Enter `winrm quickconfig` and choose yes. To enable PowerShell remoting, enter `Enable-PSRemoting` and either choose yes or yes to all. To check the listener status, enter `winrm enumerate winrm/config/listener`
7. On the sender Windows 7 VM, to add the target Windows 7 VM to the TrustedHosts list, use
   ```
   Set-Item WSMan:\localhost\Client\TrustedHosts -Value "<target_IP_address>"
   ```
   Or to simply allow connections to any IP address, replace the target IP address with an asterisk (*)
8. To test the PowerShell remote access from the sender VM, use the following commands
   ```
   Enter-PSSession -ComputerName <target_IP_address> -Credential (Get-Credential)
   ```
   Upon successful remote access, the PowerShell would look like this
   ![image](https://github.com/user-attachments/assets/2745445e-1719-4e77-87b0-0dc5af2afcaf)
9. In Windows 7 VM, Sysmon and its XML configuration file has to be placed in the `C:\Windows` directory. This can be confirmed when checking properties of Sysmon in Windows Services
10. 
