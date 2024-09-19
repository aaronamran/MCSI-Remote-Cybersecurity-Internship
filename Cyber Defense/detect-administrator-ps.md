# Write A PS Script That Detects Whether A Machine Has More Than 1 Local Administrator
Best practice is to have only one local administrator per machine. Multiple admin accounts increase the risk of malicious users gaining control, accessing sensitive data, or installing malware. If one admin account is compromised, others may also be at risk.



## Tasks
- Write a PowerShell script that enumerates all local user accounts on the machine
- If there is more than one user account with local administrator privileges, the script should raise an alert
- Extend the script to scan nested groups (sub-groups) that have been provided local administrator privileges
- Count the total number of local administrator accounts, including those in nested groups
- Implement a feature in the script to scan remote machines for local administrator accounts
- Allow the script to accept a list of remote machine names or IP addresses as input


## Recommended Approach
- Run the script on a local machine and demonstrate that it correctly detects multiple local administrator accounts and nested group members
- Create multiple local administrator accounts on a remote machine
- Run the script against the remote machine and validate its ability to detect multiple local administrator accounts and nested group members


