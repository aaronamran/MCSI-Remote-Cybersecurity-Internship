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
1. 
