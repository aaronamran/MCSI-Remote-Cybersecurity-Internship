# Nmap
Nmap will return "open|filtered" when it is unable to determine whether a port is open or filtered

## Perform a TCP Port Scan Using Nmap

#### Preparation
- Target machine: Lubuntu VM in VirtualBox
- Start "apache2" service and the "ssh" service on the target virtual machine
- Check that services are running on default ports (22 and 80)
- Check that Nmap can be used to detect open ports and the loopback address (127.0.0.1)

#### TCP Scans
- Use Nmap's TCP Connect Scan ("-sT") against the target machine to identify open ports
- Use Nmap's TCP SYN Scan ("-sS") against the target machine to identify open ports using SYN packets
- Use Nmap's Service Detection ("-sV") against the target machine to identify the services running on open ports
- Use Nmap's OS Detection ("-A") against the target machine to identify the operating system running on the target system
- Use Nmap's scan option to scan all TCP ports ("-p-") against the target machine to identify all open ports
- For each of the scans performed, ensure that Nmap successfully discovers port 22 (SSH) and port 80 (HTTP) as "open" on the target machine






## Perform a UDP Port Scan Using Nmap
#### Preparation
- Always include the "-sU" flag for UDP scans
- Combine "-sU" with other flags such as "-sV" and "-p" for detailed scanning
- Target machine: Lubuntu VM in VirtualBox
- Install and start SNMP on the target machine, and ensure that SNMP is running on default port 161
- Validate that open port(s) can be detected using Nmap with the "-sU" flag and the loopback address (127.0.0.1)

#### UDP Scans
- Perform a UDP scan against the target machine to identify open UDP ports
- Perform a UDP service detection ("-sV") against the target machine to identify associated services
- Use Nmap's scan option to scan all UDP ports ("-p-") against the target machine to identify all open ports
- For each of the scans performed, ensure that Nmap successfully discovers port 161 (SNMP) as "open" on the target machine


