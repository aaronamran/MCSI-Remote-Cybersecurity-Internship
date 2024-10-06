# Meterpreter

## Escalate Privileges To SYSTEM Using Meterpreter’s Command GETSYSTEM
Gaining SYSTEM privileges on a Windows machine is essential for penetration testers and red teamers to perform advanced post-exploitation tasks like credential dumping and accessing sensitive data. Meterpreter's GETSYSTEM command is a powerful tool for escalating privileges to SYSTEM-level access.

#### Preparation
- Target machine: Windows 7 VM with local administrator privileges
- Attacker machine: Kali Linux VM with Metasploit installed

#### Tasks
- Use MSFVenom to generate a Meterpreter reverse shell payload. Ensure you set the payload to be compatible with the target machine's architecture
- Transfer the payload to the target machine
- Create a Meterpreter listener
- On the target machine, right-click the payload file and select "Run as administrator" to start the reverse shell with elevated privileges
- Within the Meterpreter session, use the `getsystem` command to escalate your privileges to SYSTEM level
- Execute either the `whoami` or `getuid` command

#### Solutions 
1. 
