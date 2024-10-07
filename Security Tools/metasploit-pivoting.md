# Use Metasploit's Port Forwarding Capabilities To Gain Access To A Machine That Doesn't Have Direct Internet Access
Some networks isolate business-critical machines from the Internet and more vulnerable corporate systems using Virtual LANs (VLANs) or physical segmentation. Despite this isolation, network engineers and system administrators still require access to these restricted networks for tasks like troubleshooting, patching, or rebooting machines. As a penetration tester or red teamer, your goal is to identify users who need access to these restricted networks, target the machines they use for management, and compromise them. Once you gain control of a machine with access, you can route your traffic through it to reach the restricted network. This method, known as 'pivoting,' allows you to move into otherwise unreachable network environments.

## References
- [Pivoting](https://www.offsec.com/metasploit-unleashed/pivoting/) by Offensive Security

## Tasks
- Prepare the following lab setup:
  - Kali Machine (Attacker)
  - Target Machine with a Meterpreter implant (Target 1)
  - Target Machine that the Kali machine cannot directly reach, with an open port running a service (Target 2)
- Obtain a Meterpreter session on Target 1
- Within the Meterpreter session on Target 1, add a route to Target 2
- Perform a port scan against Target 2
- Validate your Attack box can communicate with Target 1, but cannot reach Target 2
- Validate your Attack box cannot see the open port and service running on Target 2
- Demonstrate that you can identify the open port and service running on Target 2 via the Meterpreter session running on Target 1

## Solutions
1. Both target machines are set to be Windows 7 64-bit, and Kali Linux should not be able to connect to Target 2
2. In Target 2, create a new custom inbound firewall rule that applies to all programs and any protocol types. The local IP addresses are kept at 'Any IP address', and the remote IP addresses that this rule applies to is the Kali Linux IP address. Block the connection and apply the rule to domain, private and public and save the rule
3. Ping Target 2 from Kali Linux to ensure 100% packet loss
4. In Kali Linux, open Metasploit, and exploit Target 1 based on the [steps provided here](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Security%20Tools/metasploit-exploit-ms17-010.md)
5. Once a Meterpreter session is opened, use `background` to background the session
6. Enter `use multi/manage/autoroute`. Enter `options` and if the Meterpreter's session ID previously is 1, enter `set SESSION 1`, and if the IP address of both Targets is 192.168.1.X, enter `set SUBNET 192.168.1.0` and `run`
7. Show the current routing table Metasploit is using with `route print` and confirm the Subnet, Netmask and Gateway information
8. Enter `scanner/portscan/tcp` and `options`. Set the RHOSTS to Target 2 and define the range of ports with RPORTS, for example `set PORTS 1-500`. Set the THREADS to 3 and run. It should return the following output:
![image](https://github.com/user-attachments/assets/bb182e9b-a896-4a73-a7e0-bfa8924fb982)

