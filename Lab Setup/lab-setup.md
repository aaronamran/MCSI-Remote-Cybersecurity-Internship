## Lab Setup

### Screen Recording
- Screen recording is done using OBS Studio: https://obsproject.com/download

### Deploy a Virtual Machine in VirtualBox
- Kali Linux is installed as attacker machine, while Windows 7 is installed as target machine
- Both VMs use NAT Network for network connectivity
- In the Windows VM, ping the Kali Linux VM

### OpenVAS
- Install Docker in Kali Linux: https://www.kali.org/docs/containers/installing-docker-on-kali/
  Individual commands:
    `sudo apt update`
    `sudo apt update install -y docker.io`
    `sudo systemctl enable docker --now`
    `docker`

- Install OpenVAS: https://greenbone.github.io/docs/latest/22.4/kali/index.html
  Troubleshooting links:
    https://greenbone.github.io/docs/latest/22.4/kali/troubleshooting.html
    https://forum.greenbone.net/t/database-gvmd-does-not-exist/18064/2
  
  If the following error appears:

  `ERROR: The Postgresql DB does not exist.`
        `FIX: Run 'sudo runuser -u postgres -- /usr/share/gvm/create-postgresql-database'`

  `ERROR: Your GVM-23.11.0 installation is not yet complete!`
  
  Become the postgres user to access psql shell:
  `sudo su postgres`

  Start the PostgreSQL shell:
  `psql`

  Input the following commands:
  `postgres=# \l`
  `postgres=# ALTER DATABASE postgres REFRESH COLLATION VERSION;`
  `postgres=# ALTER DATABASE template1 REFRESH COLLATION VERSION;`

  Exit to terminal and run
  `sudo runuser -u postgres -- /usr/share/gvm/create-postgresql-database`
  `sudo gvm-setup`
  `sudo gvm-check-setup`

  PostgreSQL problem will be solved and the following will finally appear:
  `Step 5: Checking Postgresql DB and user ... `
        `OK: Postgresql version and default port are OK.`
 `gvmd      | _gvm     | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | `
`16440|pg-gvm|10|2200|f|22.6||`
        `OK: At least one user exists.`
  .
  .
  .
  `It seems like your GVM-23.11.0 installation is OK.`


  



  
  
