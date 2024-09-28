# Write A YARA Rule That Can Find Small Portable Executables
YARA rules are powerful for threat hunting, helping detect malware by scanning systems for malicious files. When targeting Windows Portable Executables (PE files), YARA rules can identify them through their signature, .exe extension, and embedded malware. The `pe` module in YARA is useful for writing and testing rules specifically against PE files, aiding malware analysis and detection.

## References
- [Writing YARA Rules](https://yara.readthedocs.io/en/v3.8.1/writingrules.html) by VirusTotal on yara
- [PE Module](https://yara.readthedocs.io/en/v4.4.0/modules/pe.html) by VirusTotal on yara

## Tasks
1. Complete the following prerequisites first:
   - [Lab Setup: Threat Hunting With YARA](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/threat-hunting-yara.md)
   - [Write A YARA Rule That Is Professionally Documented](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/pro-documented-yara-rule.md)
2. Write a YARA rule that has the following characteristics:
   - only detect files that are Portable Executables (PEs)
   - only detect files that are less than 500KB in size
3. Save the YARA rule as "small_pe.yar" in a location on the hard drive
4. Follow along the [YARA Rules Testing Guidelines](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/pro-documented-yara-rule.md#yara-rules-testing-guidelines) and test the rule

## Benchmarks
- Ensure that the YARA rule accurately identifies small Windows Portable Executables (PEs) less than 500KB in size

## Solutions With Scripts
[Link to YARA rule](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/YARA%20rules/small_pe.yar)
1. Write the YARA rule
   ```
   import "pe"

   rule small_pe {
       meta:
           description = "Detects small Portable Executable files under 500KB"
           author = "Aaron Amran"
           date_created = "2024-09-25"
           version = "1.0"
       
       condition:
           // File size is less than 500KB(500 * 1024 bytes = 512000 bytes)
           filesize < 512000 and
           
           // File type is Portable Executable (PE)
           pe.is_pe
   }
   ```
2. Save it as `small_pe.yar` in a folder
3. To scan for portable executables in a target directory, open Command Prompt with administrator privileges and run the following commands:
   ```
   cd C:\YARA
   yara64.exe -r "C:\YARA\rules\small_pe.yar" "C:\Windows\System32"
   ```
4. The sample output will look like this:
   <br/>
   ![image](https://github.com/user-attachments/assets/2c331ac1-7d6f-45d0-bc00-cd7ee061f2af)



