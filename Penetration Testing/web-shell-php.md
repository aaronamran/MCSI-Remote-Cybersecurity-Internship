# Write A Web Shell In PHP
A PHP web shell is a script that lets a hacker remotely control a web server. Once installed, it grants access to files and allows command execution, potentially leading to full server control and attacks on other sites.

## References
- [C99 WebShell with PHP7 and MySQL Support](https://github.com/cermmik/C99-WebShell) by cermmik on GitHub
- [chopper.jsp](https://github.com/JoyChou93/webshell/blob/master/jsp/chopper.jsp) by JoyChou93 on GitHub
- [Detecting and Defeating the China Chopper Web Shell](https://www.mandiant.com/sites/default/files/2021-09/rpt-china-chopper.pdf) by Tony Lee, Ian Ahl and Dennis Hanzlik from FireEye Labs


## Tasks
- Develop a PHP backdoor that requires the operator to enter a password before allowing its use
- Implement functionality to execute malicious commands on the target web server through the PHP web shell
- Enable the PHP backdoor to accept and process file uploads onto the target web server
- Provide functionality to download files from the target web server using the PHP web shell

## Benchmarks
- Deploy your PHP web shell to a target web server (for local testing, you can use XAMPP to host the file)
- Access the PHP web shell through a web browser
- Attempt to enter an incorrect password to demonstrate the authentication function
- Successfully enter the correct password to gain access to the PHP web shell
- Demonstrate the ability to execute malicious commands by executing a simple 'dir' command on the target machine
- Emulate a scenario where an attacker uploads a malicious executable to the server
- Verify the successful transfer of the malicious executable by running it
- Simulate an attacker downloading a confidential file from a directory other than where the web server is stored (eg. C:\ or /etc/)
- Confirm that the downloaded file is received intact and matches the original file on the target web server

## Solutions With Scripts
[Link to web-shell.php](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Penetration%20Testing/scripts/web-shell.php)
- Sample of malicious executables:
  - Batch script for Windows:
    ```
    @echo off
    echo This is a simulated malicious script.
    pause
    ```
  - Shell script for Linux:
    ```
    #!/bin/bash
    echo "This is a simulated malicious script."
    ```
- Sample of confidential file stored in non-web server directories:
  - Text file:
    ```
    Confidential Document
    Name: John Doe
    SSN: 123-45-6789
    Bank Account: 9876543210
    ```
1. Login to `webshell.php` hosted on the localhost using the password `password123`. An invalid password error would appear as the following on the screen:
   ![image](https://github.com/user-attachments/assets/4834a641-3f93-4423-ad2e-3db190fa011b)
2. The homepage of the PHP web shell is shown below:
   ![image](https://github.com/user-attachments/assets/0ed8b5cb-ed1c-40f9-8820-789737728940)
3. To see the current directory, enter the command `pwd`
4. Use the command combination of `cd <directory> && ls` to list files and folders in the specified directory
5. To upload a (malicious) file, browse and click 'Upload File'
6. To download a file, identify the absolute path of the file and enter into the download text field, then click 'Download'. For example `/var/www/html/uploads/yourfile.txt
`

   







