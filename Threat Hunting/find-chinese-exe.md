# Write A YARA Rule That Identifies Chinese Executables
YARA rules are powerful tools for threat hunting, enabling quick identification of malware and malicious files. Threat hunters use them to scan systems and track infections. In the Portable Executable (PE) format, the compiler populates a field with the computer’s language ID. However, adversaries can manipulate this value to deceive threat intelligence and malware analysts.

## References
- [Language Identifier Constants and Strings](https://docs.microsoft.com/en-us/windows/desktop/intl/language-identifier-constants-and-strings) by Microsoft
- [[MS-LCID]-Windows Language Code Identifier (LCID) Reference](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lcid/70feba9f-294e-491e-b6eb-56532684c37f) by Microsoft
