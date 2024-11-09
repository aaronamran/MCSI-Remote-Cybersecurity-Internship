# Write A PS Script To Disable LLMNR
LLMNR and NetBIOS are two name resolution services built in to Windows to help systems find address names from other devices on the network. However, addresses and address providers on the network are not verified, since Windows assumes that anyone on the network is automatically trusted.
For a service like SMB, if a host is configured to automatically authenticate over SMB then by spoofing addresses over LLMNR/NBT-NS, an attacker can easily grab credentials by simply passively replying to every single LLMNR/NBT-NS request


## References
- [Link-Local Multicast Name Resolution](https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution) by Wikipedia
- [How To Disable LLMNR & Why You Want To](https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/) by Black Hills Information Security


## Tasks
- Write a PowerShell script that detects whether LLMNR is enabled on a local Windows machine
- If LLMNR is enabled on the local machine, the script should disable it to enhance security
- Implement the necessary registry changes to disable LLMNR effectively
- Extend the script to allow the execution on remote Windows machines
- Provide options to input remote machine names or IP addresses
- Provide informative output messages that inform the user about the LLMNR status and the actions taken (e.g., enabled, disabled)


## Benchmarks
- Enable LLMNR on a local machine
- Run the script and demonstrate that it correctly detects and disables LLMNR on the local machine
- Enable LLMNR on a remote machine
- Run the script and demonstrate that it correctly detects and disables LLMNR on the remote machine


## Solutions With Scripts
- Save the following PowerShell script as `disableLLMNR.ps1` in a Windows 7 VM
  ```
  # PowerShell script to detect and disable LLMNR on local or remote machines
  
  # Function to check LLMNR status
  function Get-LLMNRStatus {
      param (
          [string]$ComputerName = $env:COMPUTERNAME
      )
  
      try {
          $llmnrRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
          $llmnrStatus = Get-ItemProperty -Path $llmnrRegPath -Name "EnableMulticast" -ErrorAction Stop | Select-Object -ExpandProperty EnableMulticast
          if ($llmnrStatus -eq 0) {
              Write-Output "LLMNR is currently disabled on $ComputerName."
              return $false
          }
          else {
              Write-Output "LLMNR is currently enabled on $ComputerName."
              return $true
          }
      } catch {
          Write-Output "LLMNR is not configured on $ComputerName. Defaulting to enabled."
          return $true
      }
  }
  
  # Function to disable LLMNR
  function Disable-LLMNR {
      param (
          [string]$ComputerName = $env:COMPUTERNAME
      )
  
      $llmnrRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
      if (!(Test-Path $llmnrRegPath)) {
          New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name "DNSClient" -Force | Out-Null
      }
  
      Set-ItemProperty -Path $llmnrRegPath -Name "EnableMulticast" -Value 0 -Force
      Write-Output "LLMNR has been disabled on $ComputerName."
  }
  
  # Main script execution
  Write-Output "Select an option:"
  Write-Output "1 - Detect and disable LLMNR on the local machine"
  Write-Output "2 - Detect and disable LLMNR on a remote machine"
  $choice = Read-Host -Prompt "Enter your choice (1 or 2)"
  
  if ($choice -eq "1") {
      # Local machine operation
      $llmnrEnabled = Get-LLMNRStatus -ComputerName $env:COMPUTERNAME
      if ($llmnrEnabled) {
          Disable-LLMNR -ComputerName $env:COMPUTERNAME
      }
  } elseif ($choice -eq "2") {
      # Remote machine operation
      $remoteComputer = Read-Host -Prompt "Enter the remote computer name or IP address"
      try {
          $llmnrEnabled = Invoke-Command -ComputerName $remoteComputer -ScriptBlock { 
              param ($remoteComputer)
              & {
                  function Get-LLMNRStatus {
                      param ([string]$ComputerName)
                      $llmnrRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
                      try {
                          $llmnrStatus = Get-ItemProperty -Path $llmnrRegPath -Name "EnableMulticast" -ErrorAction Stop | Select-Object -ExpandProperty EnableMulticast
                          return $llmnrStatus -eq 1
                      } catch {
                          return $true
                      }
                  }
                  Get-LLMNRStatus -ComputerName $using:remoteComputer
              }
          }
          if ($llmnrEnabled) {
              Invoke-Command -ComputerName $remoteComputer -ScriptBlock { 
                  function Disable-LLMNR {
                      $llmnrRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
                      if (!(Test-Path $llmnrRegPath)) {
                          New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name "DNSClient" -Force | Out-Null
                      }
                      Set-ItemProperty -Path $llmnrRegPath -Name "EnableMulticast" -Value 0 -Force
                  }
                  Disable-LLMNR
              }
              Write-Output "LLMNR has been disabled on $remoteComputer."
          } else {
              Write-Output "LLMNR is already disabled on $remoteComputer."
          }
      } catch {
          Write-Output "Failed to connect to $remoteComputer. Ensure that the remote machine is accessible and PowerShell remoting is enabled."
      }
  } else {
      Write-Output "Invalid input. Please enter 1 or 2."
  }
  ```
2. Set Execution Policy (if necessary): If you encounter a script execution error, use the following command to allow the script to run:
   ```
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
3. To enable PowerShell remoting between local and target VMs, get the IP address of the target remote machine. Then set it as a trusted host on the local machine to allow remote connections
   ```
   Set-Item WSMan:\localhost\Client\TrustedHosts -Value "the_other_Windows_IP_Address"
   winrm quickconfig -Force
   Enable-PSRemoting -Force
   ```
4. Enable LLMNR on a local machine by pressing going to the Registry Editor and navigate to `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`. Look for or create a DWORD value called `EnableMulticast` and set it to 1 to enable LLMNR, or 0 to disable it. If `DNSClient` does not exist under `Windows NT`, it can be created manually be right-clicking on `Windows NT`, select New > Key and name it `DNSClient`. Then create the DWORD valze by right-clicking on `DNSClient` select New > DWORD (32-bit) Value and name it `EnableMulticast` and set the values accordingly
   ![image](https://github.com/user-attachments/assets/6b08c4bf-b0aa-4dae-983a-758442b12bf9)
   <br/>
   The (Default) entry with the REG_SZ type can be ignored; as it’s a standard placeholder that appears by default when a new registry key is created. It doesn't impact the configuration for LLMNR.
6. Run the script and demonstrate that it correctly detects and disables LLMNR on the local machine
7. To enable LLMNR on a remote machine, do the same steps as in step 4 above
8. Run the script and demonstrate that it correctly detects and disables LLMNR on the remote machine
