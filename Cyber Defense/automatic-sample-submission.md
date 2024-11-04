# Write A PS Script To Turn On Automatic Sample Submission
Automatic Sample Submission is a valuable feature in Windows Defender Antivirus that allows the system to send unknown executable files to Microsoft's cloud-based malware analysis infrastructure. This feature enhances the overall security of the system by helping Microsoft detect new malware variants and create more effective security detections

## References
- [Set-MpPreference](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps&viewFallbackFrom=win10-ps)


## Tasks
- Write a PowerShell script that enables the Automatic Sample Submission feature in Windows Defender on the local machine
- Ensure that the script turns on Automatic Sample Submission if it is currently disabled
- Display a success message after enabling the feature
- Extend the script to support remote machines
- Allow the script to accept a list of remote machine names or IP addresses as input
- If a remote machine is specified, the script should remotely check the status of Automatic Sample Submission and enable it if necessary


## Benchmarks
- Disable Automatic Sample Submission on a local machine
- Run the script and demonstrate that it correctly detects and enables Automatic Sample Submission on the local machine
- Disable Automatic Sample Submission on a remote machine
- Run the script and demonstrate that it correctly detects and enables Automatic Sample Submission on the remote machine


## Solutions With Scripts
1. 
