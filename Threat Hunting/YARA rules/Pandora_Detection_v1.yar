rule Pandora_Detection_v1
{
    /*
    Rule Name: Pandora_Detection_v1
    Student ID: nxCLnZGLgyOUMpnDw16rtDvYuTF2
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
