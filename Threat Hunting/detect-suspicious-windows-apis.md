# Write A YARA Rule That Detects Suspicious Windows APIs
Analyzing Windows APIs used by malware helps identify its capabilities. PE Studio includes a default blacklist of suspicious Windows APIs in its 'functions.xml' file, which can aid in threat hunting. However, this approach may generate false positives since legitimate software also uses these APIs. Occasionally, high-fidelity YARA rules can be crafted to detect specific combinations of APIs unique to certain malware families.


## References
- [Anti-Debugging Techniques](https://medium.com/@X3non_C0der/anti-debugging-techniques-eda1868e0503) by David Ayman on Medium
- [antidebug.yar](https://github.com/DarkenCode/yara-rules/blob/master/antidebug.yar) by DarkenCode on GitHub
- [AntiDebugging.yara](https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara) by naxonez on GitHub
- [Programming reference for the Win32 API](https://learn.microsoft.com/en-us/windows/win32/api/) by Microsoft
- [How to Install the YARA Malware Analysis Tool On Windows](https://www.petergirnus.com/blog/how-to-install-yara-malware-analysis-tool-on-windows) by Peter Girnus
- [Running YARA from the command-line](https://yara.readthedocs.io/en/stable/commandline.html#cmdoption-yara-t) by VirusTotal


## Tasks
For each rule listed below, compile a list of at least 10 suspicious Windows APIs associated with the specific malware behavior.
1. Write a YARA rule that detects malware using anti-debugging techniques
2. Write a YARA rule that detects malware performing local and network enumeration (e.g., listing processes, user accounts, file shares)
3. Write a YARA rule that detects malware using code injection techniques
4. Write a YARA rule that detects spyware (e.g., keylogging, microphone recording)
5. Write a YARA rule that detects ransomware samples
6. Follow along with the 'YARA Rules Testing' guideline and test the rules
7. Compile all the rules into a single file using yarac, and run against the malware dataset
8. Validate that your YARA rules accurately detect the respective categories of malware based on the specific suspicious Windows APIs used


## Solutions With Scripts
1. YARA rule that detects malware using anti-debugging techniques
   ```
   rule Anti_Debugging_Malware
   {
       meta:
           description = "Detects malware that employs anti-debugging techniques"
           author = "Aaron Amran"
           date = "2024-10-25"
       strings:
           // Common anti-debugging strings
           $s1 = "IsDebuggerPresent" nocase
           $s2 = "NtQueryInformationProcess" nocase
           $s3 = "CheckRemoteDebuggerPresent" nocase
           $s4 = "DebugActiveProcess" nocase
           $s5 = "OutputDebugStringA" nocase
           $s6 = "CreateToolhelp32Snapshot" nocase
           $s7 = "GetThreadContext" nocase
           $s8 = "SetThreadContext" nocase
           $s9 = "VirtualProtect" nocase
           $s10 = "TerminateProcess" nocase
   
       condition:
           any of ($s*) 
   }
   ```

2. YARA rule that detects malware performing local and network enumeration (e.g., listing processes, user accounts, file shares)
   ```
   rule Local_Network_Enumeration
   {
       meta:
           description = "Detects malware performing local and network enumeration"
           author = "Aaron Amran"
           date = "2024-10-25"
       strings:
           // Common enumeration-related strings
           $s1 = "EnumProcesses" nocase
           $s2 = "NetShareEnum" nocase
           $s3 = "NetUserEnum" nocase
           $s4 = "GetUserName" nocase
           $s5 = "GetComputerName" nocase
           $s6 = "OpenProcess" nocase
           $s7 = "CreateToolhelp32Snapshot" nocase
           $s8 = "Process32First" nocase
           $s9 = "Process32Next" nocase
           $s10 = "NetLocalGroupEnum" nocase
   
       condition:
           any of ($s*)
   }
   ```
3. YARA rule that detects malware using code injection techniques
   ```
   rule Code_Injection_Malware
   {
       meta:
           description = "Detects malware using code injection techniques"
           author = "Aaron Amran"
           date = "2024-10-25"
       strings:
           // Common code injection-related strings
           $s1 = "CreateRemoteThread" nocase
           $s2 = "VirtualAllocEx" nocase
           $s3 = "WriteProcessMemory" nocase
           $s4 = "OpenProcess" nocase
           $s5 = "SetWindowsHookEx" nocase
           $s6 = "CreateProcess" nocase
           $s7 = "LoadLibrary" nocase
           $s8 = "GetProcAddress" nocase
           $s9 = "NtCreateThreadEx" nocase
           $s10 = "RtlCreateUserThread" nocase
   
       condition:
           any of ($s*)
   }
   ```
4. YARA rule that detects spyware (e.g., keylogging, microphone recording)
   ```
   rule Spyware_Detection
   {
       meta:
           description = "Detects spyware activities such as keylogging and microphone recording"
           author = "Aaron Amran"
           date = "2024-10-25"
       strings:
           // Common spyware-related strings
           $s1 = "GetAsyncKeyState" nocase
           $s2 = "GetKeyState" nocase
           $s3 = "RecordSound" nocase
           $s4 = "CreateFile" nocase
           $s5 = "OpenSoundDevice" nocase
           $s6 = "WaveInOpen" nocase
           $s7 = "WaveInStart" nocase
           $s8 = "WaveInGetNumDevs" nocase
           $s9 = "GetForegroundWindow" nocase
           $s10 = "ReadFile" nocase
   
       condition:
           any of ($s*)
   }
   ```
5. YARA rule that detects ransomware samples
   ```
   rule Ransomware_Detection
   {
       meta:
           description = "Detects ransomware samples based on known behaviors"
           author = "Aaron Amran"
           date = "2024-10-25"
       strings:
           // Common ransomware-related strings
           $s1 = "Encrypt" nocase
           $s2 = "Ransom" nocase
           $s3 = "LockFiles" nocase
           $s4 = "Decrypt" nocase
           $s5 = "Crypto" nocase
           $s6 = "Key" nocase
           $s7 = "AES" nocase
           $s8 = "RSA" nocase
           $s9 = ".locked" nocase
           $s10 = "pay" nocase
   
       condition:
           any of ($s*)
   }
   ```
6. Merged YARA rule in one `.yar` file called `windows_api.yar`
   ```
   rule Anti_Debugging_Malware
   {
       meta:
           description = "Detects malware that employs anti-debugging techniques"
           author = "Aaron Amran"
           date = "2024-10-25"
       strings:
           // Common anti-debugging strings
           $s1 = "IsDebuggerPresent" nocase
           $s2 = "NtQueryInformationProcess" nocase
           $s3 = "CheckRemoteDebuggerPresent" nocase
           $s4 = "DebugActiveProcess" nocase
           $s5 = "OutputDebugStringA" nocase
           $s6 = "CreateToolhelp32Snapshot" nocase
           $s7 = "GetThreadContext" nocase
           $s8 = "SetThreadContext" nocase
           $s9 = "VirtualProtect" nocase
           $s10 = "TerminateProcess" nocase
   
       condition:
           any of ($s*) 
   }

   
   rule Local_Network_Enumeration
   {
       meta:
           description = "Detects malware performing local and network enumeration"
           author = "Aaron Amran"
           date = "2024-10-25"
       strings:
           // Common enumeration-related strings
           $s1 = "EnumProcesses" nocase
           $s2 = "NetShareEnum" nocase
           $s3 = "NetUserEnum" nocase
           $s4 = "GetUserName" nocase
           $s5 = "GetComputerName" nocase
           $s6 = "OpenProcess" nocase
           $s7 = "CreateToolhelp32Snapshot" nocase
           $s8 = "Process32First" nocase
           $s9 = "Process32Next" nocase
           $s10 = "NetLocalGroupEnum" nocase
   
       condition:
           any of ($s*)
   }

   rule Code_Injection_Malware
   {
       meta:
           description = "Detects malware using code injection techniques"
           author = "Aaron Amran"
           date = "2024-10-25"
       strings:
           // Common code injection-related strings
           $s1 = "CreateRemoteThread" nocase
           $s2 = "VirtualAllocEx" nocase
           $s3 = "WriteProcessMemory" nocase
           $s4 = "OpenProcess" nocase
           $s5 = "SetWindowsHookEx" nocase
           $s6 = "CreateProcess" nocase
           $s7 = "LoadLibrary" nocase
           $s8 = "GetProcAddress" nocase
           $s9 = "NtCreateThreadEx" nocase
           $s10 = "RtlCreateUserThread" nocase
   
       condition:
           any of ($s*)
   }

   rule Spyware_Detection
   {
       meta:
           description = "Detects spyware activities such as keylogging and microphone recording"
           author = "Aaron Amran"
           date = "2024-10-25"
       strings:
           // Common spyware-related strings
           $s1 = "GetAsyncKeyState" nocase
           $s2 = "GetKeyState" nocase
           $s3 = "RecordSound" nocase
           $s4 = "CreateFile" nocase
           $s5 = "OpenSoundDevice" nocase
           $s6 = "WaveInOpen" nocase
           $s7 = "WaveInStart" nocase
           $s8 = "WaveInGetNumDevs" nocase
           $s9 = "GetForegroundWindow" nocase
           $s10 = "ReadFile" nocase
   
       condition:
           any of ($s*)
   }

   rule Ransomware_Detection
   {
       meta:
           description = "Detects ransomware samples based on known behaviors"
           author = "Aaron Amran"
           date = "2024-10-25"
       strings:
           // Common ransomware-related strings
           $s1 = "Encrypt" nocase
           $s2 = "Ransom" nocase
           $s3 = "LockFiles" nocase
           $s4 = "Decrypt" nocase
           $s5 = "Crypto" nocase
           $s6 = "Key" nocase
           $s7 = "AES" nocase
           $s8 = "RSA" nocase
           $s9 = ".locked" nocase
           $s10 = "pay" nocase
   
       condition:
           any of ($s*)
   }
   ```

7. To use the YARA rule to scan a directory recursively (`-r`) and only report the specifically tagged rule(s) (`-t`), use the command
   ```
   yara64.exe -t Local_Network_Enumeration .\windows_api.yar  -r ".\MalwareDataset"
   ```
   Output of files detected when Malware Dataset folder is scannned using the merged YARA rule <br/>
   
