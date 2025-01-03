# Lab Setup: Reverse Engineering
Malware reverse engineering involves analyzing malicious software to understand its structure, function, and purpose, aiding in defense strategies. Common tools include disassemblers, debuggers, hex editors, and static analysis tools.


## References
- [Matthieu Suiche - DumpIt](https://storage.googleapis.com/cyber-platform-prod.appspot.com/tools/DumpIt.exe) by Matthieu Suiche
- [NSA - Ghidra](https://ghidra-sre.org/) by NSA
- [Hex-Rays - IDA](https://www.hex-rays.com/products/ida/index.shtml) by Hex-Rays
- [Marc Ochsenmeier - PE Studio](https://www.winitor.com/) by Marc Ochsenmeier
- [Microsoft - Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer) by Microsoft
- [Python Software Foundation - Python](https://www.python.org/) by Python
- [Microsoft - Strings](https://docs.microsoft.com/en-us/sysinternals/downloads/strings) by Microsoft
- [The Volatility Foundation - Volatility Framework](https://www.volatilityfoundation.org/) by The Volatility Foundation
- [Microsoft - Windbg](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/) by Microsoft
- [Wireshark Foundation - Wireshark](https://www.wireshark.org/) by Wireshark Foundation

## Tasks
Download and install the necessary tools for reverse engineering and malware analysis, and verify each tool is correctly installed and operational
- DumpIt
- Ghidra
- IDA
- PE Studio
- Process Explorer
- Python 2.7 <br/>
  prove by entering `py -2 --version` command
- Python >=3.6 <br/>
  prove by entering `python --version` command
- strings[64].exe <br/>
  - If you have a 32-bit system, copy strings.exe to C:\Windows\System32\
  - If you have a 64-bit system, rename strings64.exe to strings.exe and then copy it to C:\Windows\System32\
  ```
  strings * | findstr /i TextToSearchFor
  ```
- Volatility
- Windbg
- Wireshark <br/>
![image](https://github.com/user-attachments/assets/ad4ddaea-7354-479b-8a4c-708a9c7dea77)


