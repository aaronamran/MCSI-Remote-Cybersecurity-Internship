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



## Benchmarks
- Enable your Windows Firewall
- Run the script on your local machine
- Disable your Windows Firewall
- Run the script again on your local machine
- Start up two (2) Windows virtual machines
- Enable the Windows firewall on 1 machine
- Disable the Windows firewall on the other machine
- Create a list containing the remote machine addresses
- Scan/fix the remote hosts by passing the list to your tool



## Recommended Approach
- Firewall Enabled locally: The script running on your local machine correctly detects the Windows Firewall status as enabled
- Firewall Disabled locally: The script running on your local machine enables the Windows Firewall
- The remote hosts list scan detects the Windows firewall enabled on one machine
- The remote hosts list scan enables the Windows firewall on the vulnerable machine



