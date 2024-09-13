## Lab Setup

### Screen Recording
- Screen recording is done using OBS Studio: https://obsproject.com/download

### Deploy a Virtual Machine in VirtualBox
- Download Kali Linux: https://www.kali.org/get-kali/#kali-platforms (specific link: https://cdimage.kali.org/kali-2024.3/kali-linux-2024.3-virtualbox-amd64.7z)
- Download Windows 7: https://techpp.com/2018/04/16/windows-7-iso-official-direct-download-links/ 
- Kali Linux is installed as attacker machine, while Windows 7 is installed as target machine
- Both VMs use NAT Network for network connectivity
- Configure static IP addresses for each VMs
- In the Windows VM, ping the Kali Linux VM

### OpenVAS
- Install Docker in Kali Linux: https://www.kali.org/docs/containers/installing-docker-on-kali/<br/>
  Individual commands:<br/>
    `sudo apt update`<br/>
    `sudo apt update install -y docker.io`<br/>
    `sudo systemctl enable docker --now`<br/>
    `docker`

OpenVAS on Kali Linux Installation Guide
- Install OpenVAS: https://greenbone.github.io/docs/latest/22.4/kali/index.html <br/>
  Troubleshooting links:<br/>
    https://greenbone.github.io/docs/latest/22.4/kali/troubleshooting.html<br/>
    https://forum.greenbone.net/t/database-gvmd-does-not-exist/18064/2<br/>
  
  If the following error appears:<br/>

  `ERROR: The Postgresql DB does not exist.`<br/>
        `FIX: Run 'sudo runuser -u postgres -- /usr/share/gvm/create-postgresql-database'`<br/>

  `ERROR: Your GVM-23.11.0 installation is not yet complete!`<br/>
  
  1. Become the postgres user to access psql shell:<br/>
     `sudo su postgres`<br/>

  2. Start the PostgreSQL shell:<br/>
     `psql`<br/>

  3. Input the following commands:<br/>
     `postgres=# \l`<br/>
     `postgres=# ALTER DATABASE postgres REFRESH COLLATION VERSION;`<br/>
     `postgres=# ALTER DATABASE template1 REFRESH COLLATION VERSION;`<br/>

  4. Exit to terminal and run<br/>
     `sudo runuser -u postgres -- /usr/share/gvm/create-postgresql-database`<br/>
     `sudo gvm-setup`<br/>
     `sudo gvm-check-setup`<br/>

  5. PostgreSQL problem will be solved and the following will finally appear:<br/>
     `Step 5: Checking Postgresql DB and user ... `<br/>
          `OK: Postgresql version and default port are OK.`<br/>
   `gvmd      | _gvm     | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | `<br/>
   `16440|pg-gvm|10|2200|f|22.6||`<br/>
          `OK: At least one user exists.`<br/>
     .<br/>
     .<br/>
     .<br/>
     `It seems like your GVM-23.11.0 installation is OK.`<br/>

OpenVAS via Docker on Kali Linux Installation Guide
  1. From this [video](https://www.youtube.com/watch?v=jZZhkrY0nOE), the user seems to be using OpenVAS from mikesplain <br/>

  2. Link to mikesplain's OpenVAS on docker: https://hub.docker.com/r/mikesplain/openvas/ <br/>

  3. Docker pull command <br/>
  `docker pull mikesplain/openvas` <br/>

  4. Run the command <br/>
  ```
  # latest (9)
  docker run -d -p 443:443 --name openvas mikesplain/openvas
  # 9
  docker run -d -p 443:443 --name openvas mikesplain/openvas:9
  ```

  5. Once you see a `It seems like your OpenVAS-9 installation is OK.` process in the logs, go to `https://<machinename>` <br/>
  
  6. Both username and password: admin
  
  7. To check the status of the process, run: `docker top openvas`
  
  8. In the output, look for the process scanning cert data. It contains a percentage. To run bash inside the container run:
  `docker exec -it openvas bash`


### Create a Template for a Professional Document
- Include file naming convention: <br/>
  Use the following name convention: [KEYWORD] - [TITLE] - v[VERSION].[EXTENSION]

- Guidelines for creating template:
  - Perform stakeholder analysis
  - Perform Audience, Issue, Message, Storyline (AIMS) analysis
  - Cover page
  - Professional design
  - Fonts and text sizes (Times New Roman or Arial, paragraph spacing (1.5 lines) and line spacing (1.0 line))

- GitHub repository of pentesting reports: https://github.com/juliocesarfort/public-pentesting-reports 

  



  
  
