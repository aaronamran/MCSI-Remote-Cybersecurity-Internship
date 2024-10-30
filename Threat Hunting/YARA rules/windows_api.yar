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
