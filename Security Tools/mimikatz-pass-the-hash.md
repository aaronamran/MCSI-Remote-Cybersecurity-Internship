# Use Mimikatz To Perform A Pass-The-Hash Attack
Pass-the-Hash is a potent technique attackers use to access remote servers or services by leveraging the NTLM or LanMan hash of a user's password. This vulnerability affects all Windows machines


## References
- [module - sekurlsa](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa) by Benjamin Delpy
- [module - lsadump](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump) by Benjamin Delpy
- [Performing Pass-the-Hash with Mimikatz](https://blog.stealthbits.com/passing-the-hash-with-mimikatz) by Jeff Warren
- [Pass the Hash With Mimikatz: Complete Guide](https://www.stationx.net/pass-the-hash-with-mimikatz/) by Richard Deszo on StationX
- [Resolve "Access is Denied" using PSExec with a Local Admin Account](https://www.brandonmartinez.com/2013/04/24/resolve-access-is-denied-using-psexec-with-a-local-admin-account/) by Brandon Martinez
- [Fixed: Couldn't Install PsExec Service Access Is Denied on Windows](https://www.anyviewer.com/how-to/couldnt-install-psexec-service-access-is-denied-2578.html) by Ellie on AnyViewer


## Tasks
- Prepare two Windows machines that can communicate with each other over SMB and RPC (Target 1 and Target 2)
- On each machine, create a local administrator user with the same username and password
- On Target 1, open Mimikatz and use the appropriate command to dump NTLM hashes from the LSASS and\or SAM database
- Record the NTLM hash for the local administrator user
- Use Mimikatz's "sekurlsa::pth" command to pass-the-hash and spawn a new cmd.exe session on Target 1 using the NTLM hash
- In the spawned cmd.exe session, execute ipconfig to display the IP address of Target 1
- From the spawned cmd.exe session, use PSEXEC with the NTLM hash to authenticate into Target 2
- Once authenticated into Target 2, execute ipconfig using PSEXEC to display its IP address
- Confirm successful authentication as the new user on Target 2 by executing whoami from the spawned remote shell. Ensure that whoami returns the username corresponding to the passed NTLM hash


## Benchmarks
- You can execute ipconfig from the spawned cmd.exe session on Target 1 to validate the IP address and ensure network connectivity
- You can execute ipconfig using PSEXEC from the spawned cmd.exe session on Target 2 to validate its IP address
- Upon executing whoami from the spawned remote shell on Target 2, it returns the username corresponding to the passed NTLM hash, confirming successful authentication
- You have not used a password to connect to the remote host at any point



## Solutions
1. In both Target 1 and 2, open a Command Prompt with administrator privileges, and create a new local user with the same username and password on each machine. To create a new local user with password, use `net user adminuser adminpassword /add`. To add the user to the administrator group, use `net localgroup administrators adminuser /add`. To verify the user was created, use `net localgroup administrators`.
2. Download Mimikatz on Target 1 from [this link](https://github.com/gentilkiwi/mimikatz/archive/master.zip)
3. 




