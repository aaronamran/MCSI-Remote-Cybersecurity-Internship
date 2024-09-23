# Lab Setup: Threat Hunting with YARA
Threat hunting involves proactively searching for threats in an organization's network using various tools and techniques. YARA is a key tool for identifying malware by creating rules that scan systems, detect malicious files, and track infections. Threat hunters use YARA rules to quickly spot threats. A known-safe dataset serves as a clean reference for comparing against potentially malicious datasets. The HxD Editor is used to view and edit hexadecimal data, which consists of numbers 0-9 and letters A-F.

## References
- [Virus Total - YARA](https://github.com/VirusTotal/yara/releases) by Virus Total
- [YARA](https://sourceforge.net/projects/yara.mirror/) by SourceForge
- [HxD - Freeware Hex Editor and Disk Editor](https://mh-nexus.de/en/hxd/) by mh-nexus


## Tasks
- Download the latest version of YARA
- Download legitimate ISO installers for Windows 10 and two older Windows versions (eg: Windows 7, Windows 8, Windows 8.1, another version of Windows 10, etc.)
- Install all three versions of Windows into virtual machines
- Create a shared folder named "known-safe" between the three virtual machines
- From each virtual machine, copy the entire C: drive and store the files in the shared folder
- Download and install the HxD Hex Editor on your machine

## Benchmarks
- Confirm that you have yara64.exe on your machine
- Confirm that you have HxD Hex Editor installed on your machine
- Verify that you have successfully created a dataset containing at least 15GB of known good files from the installed Windows virtual machines

