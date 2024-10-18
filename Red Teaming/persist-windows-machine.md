# Persist On A Windows Machine With A Malicious User Account
Creating a malicious local account is a simple way to install a backdoor, often going unnoticed in poorly managed networks. Even if detected, it may remain due to concerns over breaking functionality. Skilled attackers may avoid giving the account admin rights, opting instead to plant a privilege escalation vulnerability for future use

## Tasks
- Create a user with an inconspicuous name that would seamlessly blend into an organization in a VM
- Initiate an RDP connection to the target system from a separate machine, utilizing the malicious account's credentials to showcase successful access
- Navigate the system's directories to emphasize the subtle nature of the malicious account's presence and the potential challenges in detection
- Generate a dummy file in a sensitive directory to simulate a security breach, demonstrating how a malicious actor might misuse this access for unauthorized file manipulation
- Show how the malicious account can be used to cover tracks, such as deleting the dummy file

## Solutions With Scripts
