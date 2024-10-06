# Perform a UDP Port Scan Using Nmap


## Preparation
- Always include the "-sU" flag for UDP scans
- Combine "-sU" with other flags such as "-sV" and "-p" for detailed scanning
- Target machine: Lubuntu VM in VirtualBox
- Install and start SNMP on the target machine, and ensure that SNMP is running on default port 161
  ```
  sudo apt update
  sudo apt install snmpd
  sudo systemctl status snmpd
  ```
  To enable SNMP to start on boot, run `sudo systemctl enable snmpd` <br/>
  
- Validate that open port(s) can be detected using Nmap with the "-sU" flag and the loopback address (127.0.0.1)
  `sudo nmap <ip_address> -sU` and `sudo nmap 127.0.0.1 -sU` <br/> 

## To Note
UDP scans in Nmap take a long time to complete the scan, because of the following: <br/>
- No Handshake Mechanism: <br/>
  Unlike TCP, which has a three-way handshake (SYN, SYN-ACK, ACK) that makes it easier to detect open ports, UDP is a connectionless protocol, which means there is no immediate feedback for closed ports
- Closed Port Response: <br/>
  For closed UDP ports, Nmap relies on receiving an ICMP "port unreachable" message from the target. Many firewalls and systems block or limit ICMP responses, causing Nmap to wait for a timeout, which adds a significant delay
- Open Port Detection: <br/>
  For open UDP ports, no packet may be sent back, so Nmap cannot easily distinguish between an open port and one where responses are blocked by a firewall. It must wait for a timeout before moving on
- Rate-limiting and Firewalls: <br/>
  Many systems impose rate limits on ICMP responses or may silently drop UDP packets to avoid scans, further increasing scan time
- Multiple Retries: <br/>
  To increase accuracy, Nmap sends multiple probes to each port, increasing overall scan time

If the attacker VM cannot detect SNMP on the target VM as shown below <br/>
```
nc 192.168.1.17 161
(UNKNOWN) [192.168.1.17] 161 (snmp) : Connection refused
```
run the commands in the following steps:
1. Find the SNMP config file: `sudo nano /etc/snmp/snmpd.conf`
2. Search for `agentAddress 127.0.0.1,[::1]` and replace to `0.0.0.0:161`
3. Restart the service: `sudo systemctl restart snmpd`


## UDP Scans
- Perform a UDP scan against the target machine to identify open UDP ports <br/>
  `sudo nmap <ip_address> -sU` 
- Perform a UDP service detection ("-sV") against the target machine to identify associated services <br/>
  `sudo nmap <ip_address> -sU -sV` 
- Use Nmap's scan option to scan all UDP ports ("-p-") against the target machine to identify all open ports <br/>
  `sudo nmap <ip_address> -sU -p-` <br/>
  If the UDP scan takes too long, it can be made faster by adding the `--min-rate` flag to increase speed and peformance <br/>
  `sudo nmap <ip_address> -sU -p- --min-rate <number>` <br/>
  The min-rate number means the number of packets sent per second. A low min-rate is more accurate, but takes longer time.
- For each of the scans performed, ensure that Nmap successfully discovers port 161 (SNMP) as "open" on the target machine <br/>
  Sample screenshot of Kali Linux (attacker VM) using Nmap to scan SNMP ports on Lubuntu (target VM): <br/>
  ![nmap-udp](https://github.com/user-attachments/assets/0d3b1f5b-c870-4c9c-84d4-e6380df2368a)

