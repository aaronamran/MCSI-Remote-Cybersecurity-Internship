# Write A PS Script That Detects Installed Anti-Virus Software
Detecting installed antivirus software on Windows is essential for security professionals to assess system protection against threats. A PowerShell script can retrieve information about installed antivirus, providing insights into an organization's security posture.

## References
- [How to get Antivirus information with WMI (VBScript)](https://learn.microsoft.com/en-us/archive/blogs/alejacma/how-to-get-antivirus-information-with-wmi-vbscript) by Microsoft

## Tasks
- Write a PowerShell script that retrieves information about installed anti-virus software on a local Windows machine
- Enhance the script to include the option of executing it on a remote Windows machine
- Utilize WMI or PowerShell cmdlets (e.g., Get-WmiObject, Get-CimInstance) to gather information about installed software
- Parse the information retrieved to identify the presence of anti-virus software
- Display the list of detected anti-virus software on the console
- Provide clear and descriptive output, including the name of the anti-virus software and its status (enabled or disabled)

## Benchmarks
- Ensure an anti-virus software is installed on your local machine
- Run the script on your local machine and demonstrate that it correctly detects the presence of the anti-virus software
- Ensure an anti-virus software is installed on a remote machine
- Run the script against the remote machine and demonstrate that it correctly detects the presence of anti-virus software


## Solutions With Scripts
1. Save the following PowerShell script as `detect-antivirus.ps1` on a local Windows 7 VM
   ```
    # Function to interpret product state and determine if AV is enabled based on SecurityCenter2
    function Get-AntiVirusStatus {
      param(
          [int]$productState
      )
    
      # Check if the product is enabled by inspecting the second nibble of productState
      $enabled = ($productState -band 0x10) -ne 0
      return $enabled
    }
    
    # Function to get antivirus information using SecurityCenter2
    function Get-AntiVirusInfo {
      param(
          [string]$ComputerName = $env:COMPUTERNAME
      )
    
      try {
          # Query SecurityCenter2 for antivirus products
          $antivirusInfo = Get-WmiObject -Namespace "Root\SecurityCenter2" -Class AntiVirusProduct -ComputerName $ComputerName
    
          if ($antivirusInfo) {
              foreach ($av in $antivirusInfo) {
                  Write-Host "Anti-Virus Software: $($av.displayName)" -ForegroundColor Magenta
              }
          } else {
              Write-Host "No anti-virus software detected in SecurityCenter2." -ForegroundColor Yellow
          }
      } catch {
          Write-Host "Error retrieving anti-virus information from SecurityCenter2. Checking services as fallback." -ForegroundColor Red
      }
    }
    
    # Fallback function to check for installed antivirus services status
    function Check-AntiVirusServiceStatus {
      param(
          [string]$ComputerName = $env:COMPUTERNAME
      )
    
      try {
          $services = Get-Service -ComputerName $ComputerName | Where-Object { $_.DisplayName -match "AV|antivirus|Security" }
    
          if ($services) {
              $allRunning = $true  # Initialize flag to track if all services are running
    
              foreach ($service in $services) {
                  Write-Host "Service: $($service.DisplayName) - Status: $($service.Status)" -ForegroundColor Gray
                  if ($service.Status -ne "Running") {
                      $allRunning = $false  # Set flag to false if any service is not running
                  }
              }
    
              # Output the Real-Time Protection status after checking all services
              if ($allRunning) {
                  Write-Host "Real-Time Protection: Enabled" -ForegroundColor Green
              } else {
                  Write-Host "Real-Time Protection: Disabled" -ForegroundColor Red
              }
          } else {
              Write-Host "No antivirus services found." -ForegroundColor Yellow
          }
      } catch {
          Write-Host "Error retrieving antivirus service status." -ForegroundColor Red
      }
    }
    
    # Prompt user for local or remote machine choice
    $choice = Read-Host "Choose an option: 1 for Local Machine, 2 for Remote Machine"
    
    if ($choice -eq "1") {
      Write-Host "Running on local machine..." -ForegroundColor Yellow
      Get-AntiVirusInfo
      Check-AntiVirusServiceStatus
    } elseif ($choice -eq "2") {
      $remoteMachine = Read-Host "Enter the name or IP address of the remote machine"
      Write-Host "Running on remote machine: $remoteMachine..." -ForegroundColor Yellow
      Get-AntiVirusInfo -ComputerName $remoteMachine
      Check-AntiVirusServiceStatus -ComputerName $remoteMachine
    } else {
      Write-Host "Invalid input. Please choose option 1 or 2." -ForegroundColor Red
    }
   ```
2. 
