# Write A YARA Rule That Can Find Improperly Signed Executables
YARA rules help detect malware by defining specific patterns, widely used by antivirus programs, incident response teams, and security researchers. To identify binaries pretending to be signed by Microsoft or those with invalid signatures, YARA rules can be written to detect such cases.

## Tasks
1. Complete the following prerequisites first:
   - [Lab Setup: Threat Hunting With YARA](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/threat-hunting-yara.md)
   - [Lab Setup: Malware Dataset](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/malware-dataset.md)
   - [Write A YARA Rule That Is Professionally Documented](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/pro-documented-yara-rule.md)
2. Write a YARA rule that generically detects improperly signed executables using pe.signatures
3. Save the YARA rule as "small_pe.yar" in a location on the hard drive
4. Follow along the [YARA Rules Testing Guidelines](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/pro-documented-yara-rule.md#yara-rules-testing-guidelines) and test the rule
5. Ensure the YARA rule accurately identifies improperly signed executables
6. Open one of the samples detected by the YARA rule in [PE Studio](https://www.winitor.com/download) and verify that the signature is indeed invalid

## Solutions With Scripts
