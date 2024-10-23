# Write A PS Script To Turn On Windows Defender
Windows Defender, pre-installed on Windows 10, protects against malware and online threats. Its "Real-time Protection" feature continuously monitors for infections and suspends suspicious programs automatically.


## References
- [Manage Windows Defender using PowerShell](https://learn.microsoft.com/en-us/archive/technet-wiki/52251.manage-windows-defender-using-powershell) by Microsoft
- [Running Remote Commands](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/running-remote-commands?view=powershell-7.4&viewFallbackFrom=powershell-7) by Microsoft
  

## PowerShell Script Requirements
- Checks the current status of the Windows Defender on a local machine
- If Windows Defender is enabled, displays a message indicating that it is already enabled
- If Windows Defender is not enabled, proceeds to enable it
- Implements the logic to turn on the Windows Defender programmatically
- After enabling Windows Defender, includes the logic to force it to update itself
- Displays a success message once Windows Defender is enabled and updated
- Supports remote machines
- Accepts a list of remote machine names or IP addresses as input



## Recommended Approach
- Enable your Windows Defender
- Run the script on your local machine
- Disable your Windows Defender
- Run the script again on your local machine
- Start up two (2) Windows virtual machines
- Enable Windows Defender on 1 machine
- Disable Windows Defender on the other machine
- Create a list containing the remote machine addresses
- Scan/fix the remote hosts by passing the list to your tool


## Benchmarks
- Defender Enabled locally: The script running on your local machine correctly detects Windows Defender status as enabled
- Defender Disabled locally: The script running on your local machine enables Windows Defender and updates itself
- Ensure that real-time protection is enabled after turning on Windows Defender
- The remote hosts list scan detects Windows Defender enabled on one machine
- The remote hosts list scan enables Windows Defender on the vulnerable machine and updates itself


## Solutions With Scripts
1. Save and run the following PowerShell script as `enable-defender.ps1`
   ```
    # Function to check Windows Defender status
    function Check-WindowsDefenderStatus {
        param ($ComputerName)
    
        $status = Get-MpComputerStatus -CimSession $ComputerName
        if ($status.AntivirusEnabled) {
            Write-Host "Windows Defender is already enabled on $ComputerName."
            return $true
        } else {
            Write-Host "Windows Defender is disabled on $ComputerName. Enabling it now..."
            return $false
        }
    }
    
    # Function to enable Windows Defender and update it
    function Enable-WindowsDefender {
        param ($ComputerName)
    
        # Enable Windows Defender (Real-Time Protection)
        Invoke-CimMethod -Namespace "root/Microsoft/Windows/Defender" -ClassName "MSFT_MpPreference" -MethodName "Enable" -CimSession $ComputerName
        Write-Host "Windows Defender has been enabled on $ComputerName."
    
        # Update Windows Defender
        Update-MpSignature -CimSession $ComputerName
        Write-Host "Windows Defender has been updated on $ComputerName."
    }
    
    # Main script logic to handle local and remote machines
    function Main {
        param (
            [string[]]$ComputerNames = @('localhost')  # Default to localhost if no remote machines are provided
        )
    
        foreach ($Computer in $ComputerNames) {
            try {
                # Check if Windows Defender is enabled
                $isEnabled = Check-WindowsDefenderStatus -ComputerName $Computer
    
                # If Defender is not enabled, enable it and update
                if (-not $isEnabled) {
                    Enable-WindowsDefender -ComputerName $Computer
                }
            }
            catch {
                Write-Host "Error: Unable to check or enable Windows Defender on $Computer. Error details: $_"
            }
        }
    
        Write-Host "Task completed."
    }
    
    # Example: Call the main function with a list of computer names
    # Replace with your remote machine names or IP addresses
    $computers = @('localhost', 'RemoteMachine1', 'RemoteMachine2')
    Main -ComputerNames $computers
   ```
2. 


