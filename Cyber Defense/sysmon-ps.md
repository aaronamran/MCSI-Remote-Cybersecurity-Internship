# Write A PS Script That Copies Sysmon To Remote Machines And Installs It With A Given Configuration File
Windows Sysmon logs system activity, including processes, network connections, and file access, helping detect malware and malicious activity. The Sysmon configuration file defines what events are logged, making it useful for monitoring, troubleshooting, and investigating security incidents

## References
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) by Microsoft
- [Sysmon Events](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events) by Microsoft
- [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) by Microsoft
- [Autorunsc Usage](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns#autorunsc-usage) by Microsoft
- [sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) by SwiftOnSecurity on GitHub
- [How To Easily Analyze Your Sysmon Logs](https://www.gigasheet.com/post/how-to-easily-analyze-your-sysmon-logs#:~:text=Start%20making%20some%20noise%20on,That's%20it.) by Syed Hasan on gigasheet


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
1. PowerShell script that copies Sysmon to the remote Windows machine, installs Sysmon with a given configuration file and verifies if Sysmon is running and logs the specified events
   ```
   # Variables
   $remoteMachine = "RemoteMachineNameOrIP"   # Replace with the IP or hostname of the Windows 10 VM
   $sysmonExecutable = "C:\Path\To\Sysmon64.exe"   # Local path to Sysmon executable
   $configFile = "C:\Path\To\sysmon-config.xml"   # Local path to the Sysmon configuration file
   $remoteSysmonPath = "\\$remoteMachine\C$\Sysmon64.exe"
   $remoteConfigPath = "\\$remoteMachine\C$\sysmon-config.xml"
   $credential = Get-Credential   # Prompt for credentials to access the remote machine
   
   # Step 1: Copy Sysmon executable to remote machine
   Copy-Item -Path $sysmonExecutable -Destination $remoteSysmonPath -Credential $credential
   
   # Step 2: Copy Sysmon configuration file to remote machine
   Copy-Item -Path $configFile -Destination $remoteConfigPath -Credential $credential
   
   # Step 3: Install Sysmon on the remote machine with the configuration file
   Invoke-Command -ComputerName $remoteMachine -Credential $credential -ScriptBlock {
       $sysmonPath = "C:\Sysmon64.exe"
       $configPath = "C:\sysmon-config.xml"
       Start-Process -FilePath $sysmonPath -ArgumentList "/accepteula -i $configPath" -Wait
   }
  
   # Step 4: Verify Sysmon installation
   Invoke-Command -ComputerName $remoteMachine -Credential $credential -ScriptBlock {
       Get-Process -Name sysmon
       Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
   }
   
   # Step 5: Validate configuration
   Invoke-Command -ComputerName $remoteMachine -Credential $credential -ScriptBlock {
       $configPath = "C:\sysmon-config.xml"
       if (Test-Path $configPath) {
           Write-Host "Sysmon configuration file exists on the remote machine."
       } else {
           Write-Host "Sysmon configuration file is missing!"
       }
   }
   ```
2. XML configuration file that captures unauthorised READ/WRITE access to lsass.exe, process command line execution arguments, drivers that are loaded and DLL that processes load
   ```
   <Sysmon schemaversion="4.60">
    <EventFiltering>
  
      <!-- Log unauthorized read/write access to lsass.exe -->
      <FileAccess onmatch="exclude">
        <Image condition="is">C:\Windows\System32\lsass.exe</Image>
      </FileAccess>
  
      <!-- Capture command line arguments -->
      <ProcessCreate onmatch="include">
        <CommandLine condition="contains">*</CommandLine>
      </ProcessCreate>
  
      <!-- Log drivers loaded -->
      <DriverLoad onmatch="include">
        <ImageLoaded condition="contains">C:\Windows\System32\Drivers\*.sys</ImageLoaded>
      </DriverLoad>
  
      <!-- Log DLLs loaded -->
      <ImageLoad onmatch="include">
        <Image condition="contains">C:\Windows\System32\*.dll</Image>
      </ImageLoad>
  
    </EventFiltering>
   </Sysmon>
   ```

