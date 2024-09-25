# Write A YARA Rule That Can Find Small Portable Executables
YARA rules are powerful for threat hunting, helping detect malware by scanning systems for malicious files. When targeting Windows Portable Executables (PE files), YARA rules can identify them through their signature, .exe extension, and embedded malware. The `pe` module in YARA is useful for writing and testing rules specifically against PE files, aiding malware analysis and detection.

## References
- [Writing YARA Rules](https://yara.readthedocs.io/en/v3.8.1/writingrules.html) by VirusTotal on yara
- [PE Module](https://yara.readthedocs.io/en/v3.8.1/modules/pe.html) by VirusTotal on yara

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
- 


