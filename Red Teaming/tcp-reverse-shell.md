# Write A TCP Reverse-Shell As A Windows Executable
Reverse shells are a common malware tool used by cyber adversaries. In this exercise, you'll learn to write a key offensive security tool for Red Teaming and penetration testing. A TCP reverse shell establishes a connection via TCP, allowing attackers to exploit vulnerabilities and execute commands on the target machine to gain control

## References
- [Reverse Connection](https://en.wikipedia.org/wiki/Reverse_connection) by Wikipedia

## Tasks
- Write a custom program to establish a reverse shell via TCP from a target machine to a controller machine, with the capability to execute commands, upload and download files. The reverse shell program has two components - server and client
- Setup 1 VM (Kali Linux) as controller machine that runs the server component
- Setup 1 VM (Windows 10) to operate as target that runs the client component
- Research what reverse shells are and how they work
  - What is a reverse shell?
  - How are reverse shells deployed on a target?
  - What capabilities does a reverse shell provide?
  - How can a reverse shell be created?
  - What software utilities can be incorporated into a reverse shell's functionality?
  - How do reverse shells evade detection?
- Ensure that the reverse shell has the following capabilities
  - The client connects to the server via TCP
  - On the server, the user can execute commands on the target
  - On the server, the user can upload files to the target
  - On the server, the user can download files from the target
- Requirements of the reverse shell
  - The reverse shell does not rely on third-party functionality (netcat, HTTP, meterpreter)
  - The reverse shell must implement command line formats similar to those used by Meterpreter (e.g., shell, download, upload)
  - The reverse shell must accommodate file uploads and downloads of any size
- Execute the reverse shell
  - Execute all components of your reverse shell
  - From the server, execute commands on the target
  - From the server, upload files to the target
  - From the server, download files from the target


## Benchmarks
- Validate that the target machine connects back to the server via the TCP reverse shell
- Validate that you can execute commands on the server and view information about the target
- Validate that you can upload files to the target from the server
- Validate that you can download files from the target to the server


## Solutions With Scripts
