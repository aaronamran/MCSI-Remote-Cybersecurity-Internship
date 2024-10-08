# Use Mimikatz To Perform A Pass-The-Hash Attack
Pass-the-Hash is a potent technique attackers use to access remote servers or services by leveraging the NTLM or LanMan hash of a user's password. This vulnerability affects all Windows machines

## References
- [module - sekurlsa](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa) by Benjamin Delpy
- [module - lsadump](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump) by Benjamin Delpy
- [Performing Pass-the-Hash with Mimikatz](https://blog.stealthbits.com/passing-the-hash-with-mimikatz) by Jeff Warren

## Tasks
- Prepare two Windows machines that can communicate with each other over SMB and RPC (Target 1 and Target 2)
- On each machine, create a local administrator user with the same username and password
- On Target 1, use Mimikatz to dump NTLM hashes from the LSASS and\or SAM database
- Record the NTLM hash for the local administrator user
- Use Mimikatz's "sekurlsa::pth" command to pass-the-hash and spawn a new cmd.exe session on Target 1 using the NTLM hash
- From the spawned cmd.exe session, use PSEXEC with the NTLM hash to authenticate into Target 2

## Benchmarks
- You can execute ipconfig from the spawned cmd.exe session on Target 1 to validate the IP address and ensure network connectivity
- You can execute ipconfig using PSEXEC from the spawned cmd.exe session on Target 2 to validate its IP address
- Upon executing whoami from the spawned remote shell on Target 2, it returns the username corresponding to the passed NTLM hash, confirming successful authentication
- You have not used a password to connect to the remote host at any point
- Open Mimikatz on Target 1 and use the appropriate command to dump NTLM hashes from the LSASS and/or SAM database
- Use Mimikatz's "sekurlsa::pth" command to spawn a new cmd.exe session on Target 1 using the NTLM hash
- In the spawned cmd.exe session, execute ipconfig to display the IP address of Target 1
- Use PSEXEC from the spawned cmd.exe session to authenticate into Target 2 using the NTLM hash
- Once authenticated into Target 2, execute ipconfig using PSEXEC to display its IP address
- Confirm successful authentication as the new user on Target 2 by executing whoami from the spawned remote shell. Ensure that whoami returns the username corresponding to the passed NTLM hash


## Solutions
1. 





