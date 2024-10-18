# Exclude A Folder From Anti-Virus Scanning And Run Mimikatz From There
Malware evades detection by running from excluded folders, helping it avoid antivirus scans and remain undetected, increasing the chances of malicious activity going unnoticed

## Tasks
- Set up a Windows virtual machine (VM) for this task
- Select and install an antivirus software on the VM (Windows Defender is suitable)
- Create a dedicated folder on the VM
- Configure the antivirus software to exclude this folder from scanning for malicious programs
- Download the software package for mimikatz
- Attempt to execute mimikatz from a location not excluded from AV scanning
- Download mimikatz and store it in the folder excluded from antivirus scanning
- Execute mimikatz from within the excluded location

## Solutions With Scripts
1. In Windows 10 VM, create a folder named 'Excluded Folder'
2. Search and open Windows Security. Disable 'Virus & threat protection' and 'Firewall & network protection' temporarily
3. Download Mimikatz and move it into the excluded folder
4. In 'Virus & threat protection', under 'Virus & threat protection settings', click Manage settings
5. Under Exclusions, click Add or remove exclusions
6. Click '+ Add an exclusion' select Folder and choose the Excluded Folder created earlier
7. Run Mimikatz in the excluded folder. If Mimikatz is still blocked by Windows Defender, navigate to Windows Security and open Virus & threat protection
8. Under Current threats, click on Allowed threats
9. Click on Protection history and search for the Mimikatz threat listed. Click on Actions and allow Mimikatz 

Screenshot of Mimikatz running after configured to be allowed
![image](https://github.com/user-attachments/assets/b57935fd-ce52-44d3-8874-17c29c605905)
