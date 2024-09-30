# Metasploit
Metasploit is a flexible platform used for penetration testing and security auditing, enabling testers to uncover system vulnerabilities and evaluate security measures. The framework includes multiple modules that can be used together to perform various tasks, such as detecting and exploiting weaknesses.

## Use Metasploit To Identify A Machine Vulnerable To MS17-010
The MS17-010 EternalBlue vulnerability is a serious remote code execution flaw in the Windows Server Message Block (SMB) protocol. Exploiting this vulnerability allows attackers to run arbitrary code on the target machine, potentially leading to system compromise and unauthorized access.

#### References
- [MS17-010 SMB RCE Detection](https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb_ms17_010/) by Rapid7
- [Microsoft Security Bulletin MS17-010 - Critical](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010) by Microsoft
  
#### Tasks
- Launch a VM running a vulnerable version of Windows (Windows 7)
- Within the Metasploit console, use the auxiliary module "scanner/smb/smb_ms17_010" to scan the target machine for the MS17-010 vulnerability
- Validate the output from the "MS17-010 SMB RCE Detection" auxiliary module in Metasploit is 'Host is LIKELY vulnerable to MS17-010!'

Screenshot of Metasploit successfully identifying MS17-010 vulnerability shown below: <br/>
![Metasploit identifying MS17-010 vulnerability](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Security%20Tools/images/metasploit-identify-ms17-010.png)



## Use Metasploit To Exploit MS17-010
The EternalBlue exploit targets a vulnerability in the Server Message Block (SMB) protocol, which was patched with the MS17-010 update. However, many systems remain unpatched, leaving them susceptible to this attack. The exploit can be delivered via phishing emails or malicious websites. Penetration testers can use Metasploit to identify hosts vulnerable to the EternalBlue exploit by scanning for the MS17-010 flaw. Once a vulnerable system is found, the tester can deploy and execute a malicious payload on the target using Metasploit.

#### Tasks
- Execute the appropriate MS17-010 exploit from Metasploit against the target machine to exploit the vulnerability
- Use the "getuid" command within the Meterpreter session
- After successful exploitation, verify that you have gained a Meterpreter session
- Demonstrate you are running as "NT AUTHORITY\SYSTEM" when executing "getuid" within the Meterpreter session

#### Solutions
1. Launch Metasploit in Kali Linux with the command `msfconsole`
2. Run the command `search ms17-010`
3. Choose a module. For automatic modules, simply enter `use 0`. Note that since no payload was configured, it defaults to `windows/x64/meterpreter/reverse_tcp`
4. Enter `show payloads`, and choose a payload number 26 `payload/windows/x64/meterpreter/bind_tcp_rc4`
5. To set the target's IP address, enter `show options` and `set RHOSTS <target_IP_address>`
6. (Optional) Enter `set GroomAllocations 10` and `set GroomDelta 5` for controlling how memory is arranged on the target computer during an exploit. GroomAllocations decides how many memory spaces the exploit creates to prepare the computer's memory, while GroomDelta fine-tunes the size of the memory spaces

Screenshot of Metasploit successfully exploiting MS17-010 vulnerability with an active Meterpreter session shown below: <br/>
![image](https://github.com/user-attachments/assets/6c8cfafb-7834-4b86-8c90-dbfe87114ffe)



## Use Metasploit's Port Forwarding Capabilities To Gain Access To A Machine That Doesn't Have Direct Internet Access
Some networks isolate business-critical machines from the Internet and more vulnerable corporate systems using Virtual LANs (VLANs) or physical segmentation. Despite this isolation, network engineers and system administrators still require access to these restricted networks for tasks like troubleshooting, patching, or rebooting machines. As a penetration tester or red teamer, your goal is to identify users who need access to these restricted networks, target the machines they use for management, and compromise them. Once you gain control of a machine with access, you can route your traffic through it to reach the restricted network. This method, known as 'pivoting,' allows you to move into otherwise unreachable network environments.

