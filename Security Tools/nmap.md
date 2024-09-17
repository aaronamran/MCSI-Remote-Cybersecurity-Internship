# Nmap

Nmap is a powerful tool for network exploration and security auditing, commonly used to discover hosts, services, and potential security vulnerabilities within a network. Nmap will return "open|filtered" when it is unable to determine whether a port is open or filtered.

## Perform a TCP Port Scan Using Nmap

#### Preparation
- Target machine: Lubuntu VM in VirtualBox
- Start "apache2" service and the "ssh" service on the target virtual machine
  - If "apache2" service is not installed, run the following commands step by step:
    ```
    sudo apt update
    sudo apt install apache2
    sudo systemctl start apache2
    sudo systemctl status apache2
    ```
    To enable Apache2 to start on boot, run `sudo systemctl enable apache2` <br/>

  - If "ssh" service is not installed, run the following commands step by step: <br/>
    Check for installed packages using dpkg or apt. If openssh-server is installed, it will be listed in the output
    `dpkg -l | grep openssh-server`
    `apt list --installed | grep openssh-server`

    Commands to be run in terminal: <br/>
    ```
    sudo apt update
    sudo apt install openssh-server
    sudo systemctl start ssh
    sudo systemctl status ssh
    ```
    To enable ssh to start on boot, run `sudo systemctl enable ssh` <br/>
    
- Check that services are running on default ports (ssh on port 22 and apache2 (HTTP server) on port 80)
- Check that Nmap can be used to detect open ports and the loopback address (127.0.0.1) <br/>
  `nmap <ip_address> -p 22,80` and `nmap 127.0.0.1`

#### TCP Scans
- Use Nmap's TCP Connect Scan ("-sT") against the target machine to identify open ports <br/>
  `nmap <ip_address> -sT`
  
- Use Nmap's TCP SYN Scan ("-sS") against the target machine to identify open ports using SYN packets <br/>
  `sudo nmap <ip_address> -sS` <br/>
  `sudo` is required because only root users can send special network packets that need low-level access to the network. The scan avoids completing the full connection handshake, which requires sending and managing raw packets directly.
  
- Use Nmap's Service Detection ("-sV") against the target machine to identify the services running on open ports <br/>
  `nmap <ip_address> -sV`

- Use Nmap's OS Detection ("-A") against the target machine to identify the operating system running on the target system <br/>
  `nmap <ip_address> -A`

- Use Nmap's scan option to scan all TCP ports ("-p-") against the target machine to identify all open ports <br/>
  `nmap <ip_address> -p-`

- For each of the scans performed, ensure that Nmap successfully discovers port 22 (SSH) and port 80 (HTTP) as "open" on the target machine <br/>
  Sample screenshot of Kali Linux (attacker VM) using Nmap to scan Apache2 and SSH ports on Lubuntu (target VM): <br/>
  ![Nmap TCP Scan](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Security%20Tools/images/nmap-tcp.png)





## Perform a UDP Port Scan Using Nmap
#### Preparation
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

#### To Note
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


#### UDP Scans
- Perform a UDP scan against the target machine to identify open UDP ports <br/>
  `sudo nmap <ip_address> -sU` 
- Perform a UDP service detection ("-sV") against the target machine to identify associated services <br/>
  `sudo nmap <ip_address> -sU -sV` 
- Use Nmap's scan option to scan all UDP ports ("-p-") against the target machine to identify all open ports <br/>
  `sudo nmap <ip_address> -sU -p-`
  If the UDP scan takes too long, it can be made faster by adding the `--min-rate` flag to increase speed and peformance <br/>
  `sudo nmap <ip_address> -sU -p- --min-rate <number>`
  The min-rate number means the number of packets sent per second. A low min-rate is more accurate, but takes longer time.
- For each of the scans performed, ensure that Nmap successfully discovers port 161 (SNMP) as "open" on the target machine <br/>
  Sample screenshot of Kali Linux (attacker VM) using Nmap to scan SNMP ports on Lubuntu (target VM): <br/>

