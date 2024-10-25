# Write A HTTPS Reverse-Shell As A Windows Executable
An HTTPS reverse shell is a tool hackers use to remotely control a target computer by establishing a secure connection via a crafted HTTPS URL. Once accessed, it opens a reverse shell on the hacker’s system, allowing remote access to view or modify the target’s files more securely than a plaintext HTTP connection


## References
- [Reverse Connection](https://en.wikipedia.org/wiki/Reverse_connection) by Wikipedia


## Tasks
- Develop a program that constructs a HTTPS reverse shell in the form of a Windows executable. The program must achieve the following
  - Facilitate reverse connections over HTTPS to ensure secure communication
  - Provide functionality to execute remote commands on the target machine
  - Implement the capability to upload files to the target machine
  - Incorporate the ability to download files from the target machine


## Benchmarks
- Execute the Windows executable on the attacker's machine
- Illustrate the process of establishing a reverse shell connection to the attacker's machine through HTTPS
- Demonstrate the execution of a command on the target machine to retrieve the current user's group
- Showcase the successful upload of a Sysinternals Suite executable (e.g., "PsExec.exe") from the attacker's machine to the target machine
- Validate the successful transfer of the Sysinternals Suite executable on the target machine by executing it
- Display the successful download of a sensitive file (e.g., "confidential.txt") from the target machine to the attacker's system



## Solutions With Scripts
1. 
