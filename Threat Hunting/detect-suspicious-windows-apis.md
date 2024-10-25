# Write A YARA Rule That Detects Suspicious Windows APIs
Analyzing Windows APIs used by malware helps identify its capabilities. PE Studio includes a default blacklist of suspicious Windows APIs in its 'functions.xml' file, which can aid in threat hunting. However, this approach may generate false positives since legitimate software also uses these APIs. Occasionally, high-fidelity YARA rules can be crafted to detect specific combinations of APIs unique to certain malware families.


## References
- [Anti-Debugging Techniques](https://medium.com/@X3non_C0der/anti-debugging-techniques-eda1868e0503) by David Ayman on Medium
- [antidebug.yar](https://github.com/DarkenCode/yara-rules/blob/master/antidebug.yar) by DarkenCode on GitHub
- [AntiDebugging.yara](https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara) by naxonez on GitHub
- 


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
    import "pe"
    rule Anti_Debugging_Malware
    {
        meta:
            description = "Detects malware that employs anti-debugging techniques"
            author = "Aaron Amran"
            date = "2024-10-25"
            reference = "https://github.com/DarkenCode/yara-rules/blob/master/antidebug.yar"
        strings:
            // Common anti-debugging strings
            $s1 = "IsDebuggerPresent" nocase
            $s2 = "IsDebugged" nocase
            $s3 = "NtGlobalFlags" nocase
            $s4 = "QueryInformationProcess" nocase
            $s5 = "CheckRemoteDebuggerPresent" nocase
            $s6 = "SetInformationThread" nocase
            $s7 = "DebugActiveProcess" nocase
            $s8 = "QueryPerformanceCounter" nocase
            $s9 = "GetTickCount" nocase
            $s10 = "OutputDebugString" nocase
    
        condition:
            any of ($s*) 
    }

3. YARA rule that detects malware performing local and network enumeration (e.g., listing processes, user accounts, file shares)
4. YARA rule that detects malware using code injection techniques
5. YARA rule that detects spyware (e.g., keylogging, microphone recording)
6. YARA rule that detects ransomware samples
