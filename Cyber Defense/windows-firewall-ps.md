# Write A PS Script To Turn On The Windows Firewall
The Windows firewall is software that protects a network by blocking ports and protocols that could compromise security. It can also be configured to allow specific traffic based on network needs.

## PowerShell Script Requirements
- Checks the current status of Windows Firewall on a local machine
- If the Windows Firewall is enabled, displays a message indicating that it is already enabled
- If the Windows Firewall is not enabled, proceeds to enable it
- Implements the logic to turn on the Windows Firewall programmatically
- Displays a success message if the Windows Firewall is successfully enabled
- Supports remote machines
- Accepts a list of remote machine names or IP addresses as input



## Recommended Approach
- Enable your Windows Firewall
- Run the script on your local machine
- Disable your Windows Firewall
- Run the script again on your local machine
- Start up two (2) Windows virtual machines
- Enable the Windows firewall on 1 machine
- Disable the Windows firewall on the other machine
- Create a list containing the remote machine addresses
- Scan/fix the remote hosts by passing the list to your tool



## Benchmarks
- Firewall Enabled locally: The script running on your local machine correctly detects the Windows Firewall status as enabled
- Firewall Disabled locally: The script running on your local machine enables the Windows Firewall
- The remote hosts list scan detects the Windows firewall enabled on one machine
- The remote hosts list scan enables the Windows firewall on the vulnerable machine


## Solutions With Scripts
1. Save the following PowerShell script as `check-turnon-firewall.ps1`
   ```
   # Define a function to check and enable Windows Firewall
   function Enable-WindowsFirewall {
       param (
           [string]$ComputerName = "localhost"  # Default to local machine
       )
   
       # Check if the firewall is enabled on the target machine
       $firewallStatus = Get-NetFirewallProfile -CimSession $ComputerName -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' }
   
       if ($firewallStatus) {
           Write-Output "Windows Firewall is already enabled on $ComputerName."
       } else {
           # Enable the firewall on the target machine
           try {
               Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                   Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
               }
               Write-Output "Windows Firewall has been enabled on $ComputerName."
           } catch {
               Write-Output "Failed to enable Windows Firewall on $ComputerName: $_"
           }
       }
   }
   
   # Main script logic
   Write-Output "Choose an option:"
   Write-Output "1. Perform task on local machine"
   Write-Output "2. Perform task on remote machines"
   $choice = Read-Host "Enter your choice (1 or 2)"
   
   # Option handling
   switch ($choice) {
       "1" {
           # Check and enable firewall on the local machine
           Enable-WindowsFirewall
       }
       "2" {
           # Get the list of remote machine names or IP addresses
           $remoteMachines = Read-Host "Enter a comma-separated list of remote machine names or IP addresses"
           $remoteMachinesArray = $remoteMachines -split ','
   
           # Loop through each remote machine
           foreach ($machine in $remoteMachinesArray) {
               $trimmedMachine = $machine.Trim()
               Enable-WindowsFirewall -ComputerName $trimmedMachine
           }
       }
       default {
           Write-Output "Invalid choice. Please enter either 1 or 2."
       }
   }
   ```
2.  
