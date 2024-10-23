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
   # Function to check and enable Windows Firewall
    function Enable-Firewall {
        param (
            [string[]]$RemoteComputers = @()  # Array of remote computer names or IP addresses
        )
    
        # Local computer check
        Write-Host "Checking Windows Firewall status on local machine..."
        $localStatus = Get-NetFirewallProfile -Profile Domain,Public,Private | Select-Object -ExpandProperty Enabled
    
        if ($localStatus -contains 1) {
            Write-Host "Windows Firewall is already enabled on the local machine."
        } else {
            Write-Host "Windows Firewall is disabled on the local machine. Enabling..."
            Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
            Write-Host "Windows Firewall has been enabled on the local machine."
        }
    
        # Remote computer check
        foreach ($remote in $RemoteComputers) {
            Write-Host "`nChecking Windows Firewall status on remote machine: $remote"
            try {
                $remoteStatus = Invoke-Command -ComputerName $remote -ScriptBlock {
                    Get-NetFirewallProfile -Profile Domain,Public,Private | Select-Object -ExpandProperty Enabled
                }
    
                if ($remoteStatus -contains 1) {
                    Write-Host "Windows Firewall is already enabled on $remote."
                } else {
                    Write-Host "Windows Firewall is disabled on $remote. Enabling..."
                    Invoke-Command -ComputerName $remote -ScriptBlock {
                        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
                    }
                    Write-Host "Windows Firewall has been enabled on $remote."
                }
            } catch {
                Write-Host "Failed to connect to $remote. Please check the network connection or credentials."
            }
        }
    }
    
    # Define a list of remote computers (use IP addresses or hostnames)
    $remoteMachines = @("192.168.1.101", "192.168.1.102")
    
    # Call the function for both local and remote checks
    Enable-Firewall -RemoteComputers $remoteMachines
   ```
2.  
