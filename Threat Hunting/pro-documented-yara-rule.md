# Write A YARA Rule That Is Professionally Documented
In cybersecurity, clear communication is vital. Properly documenting YARA rules ensures team members understand their purpose without needing to reverse-engineer them. Including metadata like author info, version numbers, and reference URLs enhances threat detection and response
<br/>
When documenting YARA rules, consider the following:
- Naming Convention: Use clear, descriptive names that reflect the malware targeted, enabling easy identification and organization
- Informative Comments: Add comments that explain the rule’s logic and any special considerations, helping other analysts understand its purpose and design

## References
- [Florian Roth - signature-base](https://github.com/Neo23x0/signature-base/tree/master/yara) by Florian Roth


## YARA Rules Guidelines
When documenting YARA rules, it is important to keep a few things in mind. First, be sure to use a clear and concise style, which will make the rules easy to read and understand. Additionally, be sure to use professional formatting, which will make the rules look polished and professional. Finally, be sure to document any caveats or restrictions that may be associated with the rule

- Naming Convention <br/>
Use a naming convention. We recommend that you watch the video that Kaspersky kindly provided us where they share their name convention (which is excellent)

- Use the Metadata section <br/>
YARA rules can contain a metadata section. Use it to its full potential

- Metadata: description <br/>
Enter a concise description of what the rule is meant to detect and how to best use it

- Metadata: author <br/>
Include your name and email

- Metadata: MD5/SHA1/SHA256 <br/>
Provide one or several examples of file hashes that the YARA rule is meant to detect

- Metadata: version <br/>
Include the version of the rule. For example: 0.1, 0.2, 1.0 etc

- Metadata: references <br/>
Include references to online materials that are relevant to the YARA rule (e.g. threat reports, virus total files etc.)

- Code Indentation <br/>
Properly indent your code! Make it easy for other people to read it and rapidly understand it


## YARA Rules Testing Guidelines
1. Create a test dataset and validate your rule(s) against it <br/>
Create a small dataset of less than 20 files to initially test your YARA rules against. Make sure that this dataset contains positive and negative files. Confirm with absolute certainty that your YARA rule(s) work against this dataset before moving on to the next step

2. Test your rule(s) against a large dataset <br/>
Now test your rule against a large dataset (i.e. 5GB+ of random files). This could be as simple as scanning your C: drive on Windows. Confirm that no false positives are returned

3. Test your rule(s) against a goodware and a malware dataset <br/>
If you're writing rules to detect malware samples then make sure to validate that your rules do not detect false positive by first scanning a large goodware dataset (10GB+). Only once that's been confirmed that you can scan your malware dataset


## Tasks
- Create a YARA rule using either legitimate or bogus malware data
- Professionally document your YARA rule making sure to include all the Metadata listed below
  - Author - Provide the name of the author who created the YARA rule
  - Author's email - Include the email address of the rule's author for contact purposes
  - Example of a MD5 hash - Include an example MD5 hash of a known malware sample that the rule is designed to detect
  - Date of creation - Add the date when the rule was initially written
  - Version number - Specify the version number of the YARA rule to facilitate rule updates and tracking
  - Reference URL - Include a URL to an online webpage that provides more information about the malware sample that the rule detects
  - Type of malware - Indicate the type of malware the rule detects (e.g., APT, Ransomware, Adware, etc.)

## Practical Approach
- Reference link: [Detecting Pandora Ransomware with Wazuh](https://wazuh.com/blog/detecting-pandora-ransomware-with-wazuh/) by Openime Oniagbi on Wazuh
- [Link to YARA rule](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/YARA%20rules/Pandora_Detection_v1.yar)
- Sample script:
  ```
    rule Pandora_Detection_v1
  {
      /*
      Rule Name: Pandora_Detection_v1
      Author: Aaron Amran Bin Amiruddin
      Email: aaronamranba@gmail.com
      Date of Creation: 2024-09-25
      Version: 1.0
      Description: This YARA rule is designed to detect the Pandora ransomware by matching patterns in the binary code. The rule focuses on identifying ransomware signature patterns and specific strings used during encryption routines.
      Hashes: MD5: 0c4a84b66832a08dccc42b478d9d5e1b
              SHA256: 5b56c5d86347e164c6e571c86dbf5b1535eae6b979fede6ed66b01e79ea33b7b
      Malware Type: Pandora Ransomware
      References: https://wazuh.com/blog/detecting-pandora-ransomware-with-wazuh/
      Caveats: This rule may generate false positives if non-malicious software contains similar patterns. Regularly update the rule as the ransomware evolves.
      */
  
      meta:
          author = "Aaron Amran Bin Amiruddin"
          email = "aaronamranba@gmail.com"
          date_created = "2024-09-25"
          version = "1.0"
          description = "Detects Pandora ransomware."
          md5 = "0c4a84b66832a08dccc42b478d9d5e1b"
          sha256 = "5b56c5d86347e164c6e571c86dbf5b1535eae6b979fede6ed66b01e79ea33b7b"
          malware_type = "Ransomware"
          reference = "https://wazuh.com/blog/detecting-pandora-ransomware-with-wazuh/"
  
      strings:
          $encrypt_string = "Encrypting files"    // Ransomware encryption message
          $ransom_note = "YOUR FILES HAVE BEEN ENCRYPTED" // Ransom note string
          $key_generation = { 55 8B EC 83 E4 F0 83 EC 28 A1 ?? ?? ?? ?? 33 C4 89 45 FC 56 57 8B F9 } // Mock pattern of key generation code
  
      condition:
          (uint16(0) == 0x5A4D) and  // Ensures the file is a Windows executable
          any of ($encrypt_string, $ransom_note, $key_generation)  // Matches any defined string or code pattern
  }
  ```

