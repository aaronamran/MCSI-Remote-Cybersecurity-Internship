# Perform a TCP Port Scan Using Nmap
Nmap is a powerful tool for network exploration and security auditing, commonly used to discover hosts, services, and potential security vulnerabilities within a network. Nmap will return "open|filtered" when it is unable to determine whether a port is open or filtered.



## Preparation
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

## TCP Scans
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
  ![nmap-tcp](https://github.com/user-attachments/assets/87390a83-446e-45f2-b1d8-cbc06e2d055e)

