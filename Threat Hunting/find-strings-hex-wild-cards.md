# Write A YARA Rule That Searches For Strings Using Hex And Wild-Cards
YARA rules are essential for threat hunting, enabling the identification of specific malware threats. They allow you to scan systems for malicious files and track infections, helping threat hunters swiftly pinpoint potential threats.

## References
- [Writing YARA Rules](https://yara.readthedocs.io/en/v3.8.1/writingrules.html) by VirusTotal
- [Hexadecimal Strings](https://yara.readthedocs.io/en/v3.8.1/writingrules.html#hexadecimal-strings) by VirusTotal

## Tasks
1. Complete the following prerequisites first:
   - [Lab Setup: Threat Hunting With YARA](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/threat-hunting-yara.md)
   - [Write A YARA Rule That Is Professionally Documented](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/pro-documented-yara-rule.md)
2. The YARA rule should have the following characteristics:
   - Uses hexadecimal strings
   - Uses wild-cards (??)
   - Uses a variable length ([1-4])
3. Save the YARA rule as "hex_wildcard_strings.yar" in a location on the hard drive
4. Follow along with the 'YARA Rules Testing' guideline and test the rule
5. Confirm that the rule correctly identifies files containing the specified strings using hexadecimal notation and wild-cards without false positives

## Solutions With Scripts
[Link to YARA rule](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/YARA%20rules/hex_wildcard_strings.yar)
<br/>
1. Write the following YARA rule:
   ```
   rule HexWildcardStrings {
    meta:
        description = "Detects patterns using hex strings and wildcards"
        author = "Aaron Amran"
	student_id = "nxCLnZGLgyOUMpnDw16rtDvYuTF2"
        date = "2024-09-25"
	version = "1.0"
    
    strings:
        $hex_string1 = { 68 ?? 65 6C 6C 6F }  // with wildcards
        $hex_string2 = { 77 6F 72 [1-4] 6C 64 } // with variable length

    condition:
        any of them
   }
   ```



![image](https://github.com/user-attachments/assets/b9ed6902-c265-4334-9c8d-2b4cd664f14a)

