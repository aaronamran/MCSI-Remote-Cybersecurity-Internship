# Write A YARA Rule That Can Find Itself
Threat hunting with Yara rules involves identifying and eliminating threats missed by security tools. Yara allows users to create rules to detect specific malware strains, scanning large data sets for malicious patterns. This helps organizations reduce false positives and focus on real threats.

## References
- [VirusTotal - YARA Documentation](https://yara.readthedocs.io/) by VirusTotal

## Tasks
- Complete the following prerequisites first:
  - [Lab Setup: Threat Hunting with YARA](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/threat-hunting-yara.md)
  - [Write a YARA Rule that is Professionally Documented](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/pro-documented-yara-rule.md)
- Write a YARA rule with the following string: "I love YARA"
- Save the YARA rule as "self_rule.yar" in a location on your hard drive
- Use YARA to scan your hard drive and search for files that contain the string "I love YARA" using the created rule
- Ensure that YARA successfully identifies and lists the "self_rule.yar" file containing the string "I love YARA"

