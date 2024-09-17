# Metasploit

## Use Metasploit To Identify A Machine Vulnerable To MS17-010

#### Tasks
- Launch a VM running a vulnerable version of Windows (Windows 7)
- Within the Metasploit console, use the auxiliary module "scanner/smb/smb_ms17_010" to scan the target machine for the MS17-010 vulnerability
- Validate the output from the "MS17-010 SMB RCE Detection" auxiliary module in Metasploit is 'Host is LIKELY vulnerable to MS17-010!'


## Use Metasploit To Exploit MS17-010
The Eternal Blue exploit takes advantage of a vulnerability in the Server Message Block (SMB) protocol that was fixed by the MS17-010 patch. However, many organizations have not yet installed the patch, making their systems vulnerable to attack. The exploit can be delivered through a phishing email or a malicious website.

A Penetration Tester can use Metasploit to exploit ms17-010 vulnerability by scanning for hosts that are vulnerable to the EternalBlue exploit. Once the Penetration Tester has found a vulnerable host, they can use Metasploit to upload and execute a malicious payload on the target host.

#### Tasks
- Execute the appropriate MS17-010 exploit from Metasploit against the target machine to exploit the vulnerability
- Use the "getuid" command within the Meterpreter session
- After successful exploitation, verify that you have gained a Meterpreter session
- Demonstrate you are running as "NT AUTHORITY\SYSTEM" when executing "getuid" within the Meterpreter session
