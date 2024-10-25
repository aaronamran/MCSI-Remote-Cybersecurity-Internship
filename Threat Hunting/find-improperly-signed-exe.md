# Write A YARA Rule That Can Find Improperly Signed Executables
YARA rules help detect malware by defining specific patterns, widely used by antivirus programs, incident response teams, and security researchers. To identify binaries pretending to be signed by Microsoft or those with invalid signatures, YARA rules can be written to detect such cases.


## References
- [Signaturing an Authenticode anomaly with Yara](https://www.nccgroup.com/us/research-blog/signaturing-an-authenticode-anomaly-with-yara/) by Matt Lewis on nccgroup
- [PE module](https://yara.readthedocs.io/en/stable/modules/pe.html#reference) by VirusTotal
- [PlugX USB worm](https://www.linkedin.com/posts/mgopikrish_iocsdllsideloading-plugx-usbworm-2023-03-activity-7189578122810273792-haZh/) by Gopalakrishnan Manisekaran on LinkedIn
- [Short Tutorial: How to Create a YARA Rule for a Compromised Certificate](https://www.nextron-systems.com/2018/11/01/short-tutorial-how-to-create-a-yara-rule-for-a-compromised-certificate/) by Florian Roth on Nextron Systems

## Tasks
1. Complete the following prerequisites first:
   - [Lab Setup: Threat Hunting With YARA](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/threat-hunting-yara.md)
   - [Lab Setup: Malware Dataset](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/malware-dataset.md)
   - [Write A YARA Rule That Is Professionally Documented](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/pro-documented-yara-rule.md)
2. Write a YARA rule that generically detects improperly signed executables using pe.signatures
3. Save the YARA rule as "improperly_signed_executables.yar" in a location on the hard drive
4. Follow along the [YARA Rules Testing Guidelines](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/pro-documented-yara-rule.md#yara-rules-testing-guidelines) and test the rule
5. Ensure the YARA rule accurately identifies improperly signed executables
6. Open one of the samples detected by the YARA rule in [PE Studio](https://www.winitor.com/download) and verify that the signature is indeed invalid

## Solutions With Scripts
1. An executable could be improperly signed based on the following conditions
   - Are there binaries pretending to be signed by Microsoft but are not?
   - Are there binaries that are signed but the signature is invalid?
   - Does the information in the digital signature (such as the signer's name or organisation) match the expected information for the legitimate signer?
   - Is the certificate chain incomplete or has it been tampered with? This could indicate potential manipulation of signatures
   - Has the certificate used to sign the executable expired?
   - Has the certificate used to sign the executable been revoked by the certification authority? Revocation typically occurs when the private key associated with the certificate has been compromised
2. Save the YARA rule below as `improperly_signed_executables.yar`
   ```
   import "pe"
   
   rule Improperly_Signed_Executables
   {
       meta:
           description = "Detects improperly signed executables"
           author = "Aaron Amran"
           date = "2024-10-25"
           version = "1.0"
   
       condition:
           pe.is_signed == false or
           tags contains "revoked-cert' or
           for any i in (0 .. pe.number_of_signatures) : (
           pe.signatures[i].issuer contains "Microsoft Corporation" or
           pe.signature.validation == false
           )       
   }
   ```

