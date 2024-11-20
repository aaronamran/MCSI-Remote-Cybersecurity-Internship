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

## Practical Approach
[Link to YARA rule](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/YARA%20rules/self_rule.yar)
1. Download YARA precompiled binaries for Windows from [YARA GitHub Releases](https://github.com/VirusTotal/yara/releases)
2. Download the .zip file that matches the system architecture (x64)
3. Extract the .zip file to a folder, e.g., `C:\YARA`
4. Add YARA to Path. Right-click This PC → Properties → Advanced system settings → Environment Variables. Under System variables, find the `Path` variable, click Edit, and add the folder where YARA is located, e.g., `C:\YARA`.
5. Write the YARA rule 
   ```
   rule Find_Self {
    meta:
        description = "A rule to find the YARA rule itself"
        author = "Your Name"
        date = "2024-09-25"
        reference = "Mosse Cybersecurity Institute Task"
    strings:
        $my_string = "I love YARA"
    condition:
        $my_string
   }
   ```
6. Save it as `self_rule.yar` in a folder, for example `C:\YARA\rules\self_rule.yar`
7. To scan for the file itself, open Command Prompt with administrator privileges and run the following commands:
   ```
   cd C:\YARA
   yara64.exe -r "C:\YARA\rules\self_rule.yar" "C:\YARA\rules\"
   ```
   The `yara64.exe` runs recursively to find the target file in the given directory
8. The sample output will look like this: <br/>
![image](https://github.com/user-attachments/assets/ea19077d-0433-493b-add5-bf9577296c65)



