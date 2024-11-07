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
1. Save the following PowerShell script as `check-firewall.ps1`
   ```
   # Define a function to check and enable Windows Firewall
   function Enable-WindowsFirewall {
       param (
           [string]$ComputerName = "localhost",
           [pscredential]$Credential = $null
       )
   
       if ($ComputerName -eq "localhost") {
           # Run locally without Invoke-Command
           if (Get-Command Set-NetFirewallProfile -ErrorAction SilentlyContinue) {
               Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
               Write-Output "Windows Firewall has been enabled on $ComputerName."
           } else {
               # Fallback for older systems
               netsh advfirewall set allprofiles state on
               Write-Output "Windows Firewall has been enabled on $ComputerName using netsh."
           }
       } else {
           # Use remoting for remote machines with credentials
           try {
               Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                   if (Get-Command Set-NetFirewallProfile -ErrorAction SilentlyContinue) {
                       # Enable firewall using PowerShell cmdlet if available
                       Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
                   } else {
                       # Use netsh for compatibility with older versions (e.g., Windows 7)
                       netsh advfirewall set allprofiles state on
                   }
               }
               Write-Output "Windows Firewall has been enabled on $ComputerName."
           } catch {
               Write-Output "Failed to enable Windows Firewall on $ComputerName."
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
   
           # Prompt for credentials once to use for all remote machines
           $credential = Get-Credential
   
           # Loop through each remote machine
           foreach ($machine in $remoteMachinesArray) {
               $trimmedMachine = $machine.Trim()
               Enable-WindowsFirewall -ComputerName $trimmedMachine -Credential $credential
           }
       }
       default {
           Write-Output "Invalid choice. Please enter either 1 or 2."
       }
   }
   ```
2. Open PowerShell as administrator. If necessary, set Execution Policy if you encounter a script execution error. Use the following command to allow the script to run:
   ```
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
3. To enable PowerShell remoting between local and target VMs, run each of the commands below
   ```
   winrm quickconfig -Force
   Enable-PSRemoting -Force
   ```
4. Enable firewall on the local machine and run the script. The output should be the following
   ![image](https://github.com/user-attachments/assets/fd26b77d-6b0a-4533-b760-57bd730b4ccd)
5. Disable the firewall and run the script again. It should enable the firewall automatically too
6. Start up two Windows VM. In this task, to ensure script backwards compatibility for older Windows versions (and latest versions), `netsh advfirewall` will be used instead of `Set-NetFirewallProfile`, and Windows 7 VMs will be used
7. For each Windows 7 VM, enable PowerShell remoting and get their IP address
8. Enable firewall on one machine, and disable firewall on the other machine
   ![image](https://github.com/user-attachments/assets/6f73a5b2-f6ab-411c-8ce2-f3b8352f8da8)
9. Run the `check-firewall.ps1` script and choose the second option for remote machines. Pass the IP address of both machines separated with comma and without spaces
    ![image](https://github.com/user-attachments/assets/fba212ad-f532-46f0-bac6-4ac40034299a)
10. 




