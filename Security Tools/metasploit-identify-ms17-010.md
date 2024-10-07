# Use Metasploit To Identify A Machine Vulnerable To MS17-010
The MS17-010 EternalBlue vulnerability is a serious remote code execution flaw in the Windows Server Message Block (SMB) protocol. Exploiting this vulnerability allows attackers to run arbitrary code on the target machine, potentially leading to system compromise and unauthorized access.

## References
- [MS17-010 SMB RCE Detection](https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb_ms17_010/) by Rapid7
- [Microsoft Security Bulletin MS17-010 - Critical](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010) by Microsoft
  
## Tasks
- Launch a VM running a vulnerable version of Windows (Windows 7)
- Within the Metasploit console, use the auxiliary module "scanner/smb/smb_ms17_010" to scan the target machine for the MS17-010 vulnerability
- Validate the output from the "MS17-010 SMB RCE Detection" auxiliary module in Metasploit is 'Host is LIKELY vulnerable to MS17-010!'

Screenshot of Metasploit successfully identifying MS17-010 vulnerability shown below: <br/>
![metasploit-identify-ms17-010](https://github.com/user-attachments/assets/83d65383-097c-4022-bbd7-3b8a745b6492)









