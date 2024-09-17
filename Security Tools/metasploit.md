# Metasploit
Metasploit is a flexible platform used for penetration testing and security auditing, enabling testers to uncover system vulnerabilities and evaluate security measures. The framework includes multiple modules that can be used together to perform various tasks, such as detecting and exploiting weaknesses.

## Use Metasploit To Identify A Machine Vulnerable To MS17-010
The MS17-010 EternalBlue vulnerability is a serious remote code execution flaw in the Windows Server Message Block (SMB) protocol. Exploiting this vulnerability allows attackers to run arbitrary code on the target machine, potentially leading to system compromise and unauthorized access.

#### Tasks
- Launch a VM running a vulnerable version of Windows (Windows 7)
- Within the Metasploit console, use the auxiliary module "scanner/smb/smb_ms17_010" to scan the target machine for the MS17-010 vulnerability
- Validate the output from the "MS17-010 SMB RCE Detection" auxiliary module in Metasploit is 'Host is LIKELY vulnerable to MS17-010!'


## Use Metasploit To Exploit MS17-010
The EternalBlue exploit targets a vulnerability in the Server Message Block (SMB) protocol, which was patched with the MS17-010 update. However, many systems remain unpatched, leaving them susceptible to this attack. The exploit can be delivered via phishing emails or malicious websites. Penetration testers can use Metasploit to identify hosts vulnerable to the EternalBlue exploit by scanning for the MS17-010 flaw. Once a vulnerable system is found, the tester can deploy and execute a malicious payload on the target using Metasploit.

#### Tasks
- Execute the appropriate MS17-010 exploit from Metasploit against the target machine to exploit the vulnerability
- Use the "getuid" command within the Meterpreter session
- After successful exploitation, verify that you have gained a Meterpreter session
- Demonstrate you are running as "NT AUTHORITY\SYSTEM" when executing "getuid" within the Meterpreter session
