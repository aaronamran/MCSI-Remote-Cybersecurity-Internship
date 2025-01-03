# Write A YARA Rule That Identifies Chinese Executables
YARA rules are powerful tools for threat hunting, enabling quick identification of malware and malicious files. Threat hunters use them to scan systems and track infections. In the Portable Executable (PE) format, the compiler populates a field with the computer’s language ID. However, adversaries can manipulate this value to deceive threat intelligence and malware analysts.

## References
- [Language Identifier Constants and Strings](https://docs.microsoft.com/en-us/windows/desktop/intl/language-identifier-constants-and-strings) by Microsoft
- [[MS-LCID]-Windows Language Code Identifier (LCID) Reference](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lcid/70feba9f-294e-491e-b6eb-56532684c37f) by Microsoft\
- [LCID Structure](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lcid/63d3d639-7fd2-4afb-abbe-0d5b5551eef8#Appendix_A_Target_8) by Microsoft
- [YARA PE module](https://yara.readthedocs.io/en/stable/modules/pe.html#c.language) by VirusTotal

## Tasks
1. Complete the following prerequisites first:
   - [Lab Setup: Threat Hunting With YARA](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/threat-hunting-yara.md)
   - [Lab Setup: Malware Dataset](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/malware-dataset.md)
   - [Write A YARA Rule That Is Professionally Documented](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/pro-documented-yara-rule.md)
2. Write a YARA rule that has the following characteristics:
   - Only detect files that are Portable Executables (PEs)
   - Only detect Portable Executables configured with language identifiers 0x04 or 0x004 (Chinese)
3. Save the YARA rule as "chinese_exe.yar" in a location on the hard drive
4. Follow along with the 'YARA Rules Testing' guideline and test your rule
5. Confirm that the YARA rule correctly identifies Portable Executables with language identifiers 0x04 or 0x004 (Chinese)

## Practical Approach
[Link to YARA rule](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/YARA%20rules/chinese_exe.yar)
1. Write the YARA rule
   ```
   import "pe"
   
   rule chinese_exe {
       meta:
	   description = "Detects PE files with Chinese language identifiers (0x04 or 0x004)"
	   author = "Aaron Amran"
	   date = "2024-09-28"
	   version = "1.0"

       condition:
	   // Ensure the file is a PE and has Chinese language identifier
	   pe.is_pe and
	   (pe.language(0x04) or pe.language(0x004))
    }
    ```
2. Save it as `chinese_exe.yar` in a folder
3. To scan for portable executables in a target directory, open Command Prompt with administrator privileges and run the following commands:
   ```
   cd C:\YARA
   yara64.exe -r "C:\Users\bboyz\OneDrive\Desktop\MCSI Remote Cybersecurity Internship\Threat Hunting\chinese_exe.yar" 
   "C:\Windows\System32"`
   ```
4. The sample output will look like this:
![image](https://github.com/user-attachments/assets/ed367cae-6649-4d69-b688-7c61c630c00e)

