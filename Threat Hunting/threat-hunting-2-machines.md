# Perform Threat Hunting Against 2 Machines
A threat hunter can use Python's pandas to find indicators of compromise by merging data from different sources, helping to uncover missed malicious activity. Pandas also enables data visualization through charts and graphs, revealing hidden patterns. Additionally, it allows filtering of data to focus on specific threats for further investigation.

## References
- [Reading and Writing the Apache Parquet Format](https://arrow.apache.org/docs/python/parquet.html#reading-and-writing-the-apache-parquet-format) by Apache
- [Pandas Cheat Sheet](https://pandas.pydata.org/Pandas_Cheat_Sheet.pdf) by pandas
- [What are indicators of compromise (IOCs)?](https://www.microsoft.com/en-my/security/business/security-101/what-are-indicators-of-compromise-ioc#:~:text=An%20indicator%20of%20compromise%20(IOC,data%20exfiltration%2C%20has%20already%20occurred.)) by Microsoft

## Hints
The following attacks in the dataset can be found:
- Malicious Windows commands
- Using Accessibility Features for persistence
- Modifying a Windows Service
- Searching for credentials in the registry
- Path Interception
- Process Injection

## Tasks
1. Download the threat hunting dataset provided for this exercise
2. Use Python and Pandas to analyze the dataset and identify the compromised machine
3. Use a Jupyter Notebook to perform your Threat Hunts and submit it as a PDF file as part of your submission files
4. Submit a comprehensive report adhering to the requirements below
   Your report must include the following sections:
   - Executive Summary: Provide a concise overview of your findings and the significance of identifying the compromised machine
   - Compromised Machines: Clearly state the machine you have identified as compromised, providing evidence from the dataset to support your conclusions
   - Indicators of Compromise (IOCs): Explain the identified IOCs in simple language suitable for an audience unfamiliar with threat hunting or digital forensics
   - Recommendations: Offer practical recommendations for recovering the compromised system and preventing similar attacks in the future
   - Limitations and Constraints: List any limitations or constraints you faced during your analysis, which may have impacted the scope or accuracy of your findings
   - Assumptions: Clearly state any assumptions you made while conducting your analysis

## Practical Approach
[Link to comprehensive PDF report](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/threat-hunting-2-machines/threathunting2machines.pdf) <br/>
1. To investigate the given attacks in the dataset, it is essential to know the specific indicators of compromise (IoCs) or behaviors associated with each attack
   | Attack Type	                                | Category	                                                                              | IOCs                                                               | 
   |----------------------------------------------|------------------------------------------------------------------------------------------|--------------------------------------------------------------------|
   | Malicious Windows Commands                   | Windows Processes, Windows Services                                                      | tasklist, ipconfig, systeminfo, net, query, wmic, sc, rundll32, Powershell, mshta, netstat |
   | Using Accessibility Features for Persistence | Windows Services, Windows Drivers, Windows Persistence File Items                        | narrator.exe, sethc.exe, utilman.exe, osk.exe, searchui.exe, magnify.exe, calculator.exe |
   | Modifying a Windows Service                  | Windows Services, Windows Persistence Registry Items                                     | sc, binPath, HKLM, ImagePath, FailureCommand, HKEY, svchost.exe, winlogon.exe, regedit.exe |
   | Searching for Credentials in the Registry    | Windows Persistence Registry Items, User Accounts, Windows Processes                     | reg.exe, ServiceName, Reg query, HKCU, HKLM, Lsass.exe, HKEY, PuTTY, SAM, kerberos |
   | Path Interception                            | Windows Persistence Registry Items, Windows Services                                     | %SystemRoot%, unquoted service paths |
   | Process Injection                            | Windows Processes, Windows Processes Memory Sections, Windows Persistence Registry Items | .dll, Appinit_Dlls, AppCertDlls, Image File Executable Options, HKLM\Software\Microsoft\Windows, HKLM\Software\Wow6432Node\Microsoft\Windows, AppInit_DLLs |

2. Prepare the Jupyter Notebook and in the first cell, use the following code to import libraries and declare variables
   ```
   # MRCI Threat Hunting - Perform Threat Hunting On 2 Machines

   # import dependencies
   import pandas as pd
   import pyarrow as pa
   import pyarrow.parquet as pq

   pd.set_option('display.max_colwidth', None)
   
   # convert Parquet file into a dataset
   # change backslashes in copied file path to forward slashes to prevent Unicode escape sequence errors 
   # cannot use hyphens '-' in variable names
   domainusers_dataset = pq.ParquetDataset('C:/Users/bboyz/OneDrive/Desktop/MCSI Remote Cybersecurity Internship/Threat Hunting/mcsithreathunting2machines/domain_users.parquet')
   loggedonusers_dataset = pq.ParquetDataset('C:/Users/bboyz/OneDrive/Desktop/MCSI Remote Cybersecurity Internship/Threat Hunting/mcsithreathunting2machines/loggedonusers/0000DQQEE.parquet')
   useraccounts_dataset = pq.ParquetDataset('C:/Users/bboyz/OneDrive/Desktop/MCSI Remote Cybersecurity Internship/Threat Hunting/mcsithreathunting2machines/useraccounts/0000DQQEE.parquet')
   w32drivers_dataset = pq.ParquetDataset('C:/Users/bboyz/OneDrive/Desktop/MCSI Remote Cybersecurity Internship/Threat Hunting/mcsithreathunting2machines/w32drivers/0000DQQEE.parquet')
   w32persistence_fileitems_dataset = pq.ParquetDataset('C:/Users/bboyz/OneDrive/Desktop/MCSI Remote Cybersecurity Internship/Threat Hunting/mcsithreathunting2machines/w32persistencefileitems/0000DQQEE.parquet')
   w32persistence_registryitems_dataset = pq.ParquetDataset('C:/Users/bboyz/OneDrive/Desktop/MCSI Remote Cybersecurity Internship/Threat Hunting/mcsithreathunting2machines/w32persistenceregistryitems/0000DQQEE.parquet')
   w32persistence_servicesitems_dataset = pq.ParquetDataset('C:/Users/bboyz/OneDrive/Desktop/MCSI Remote Cybersecurity Internship/Threat Hunting/mcsithreathunting2machines/w32persistenceservicesitems/0000DQQEE.parquet')
   w32processes_dataset = pq.ParquetDataset('C:/Users/bboyz/OneDrive/Desktop/MCSI Remote Cybersecurity Internship/Threat Hunting/mcsithreathunting2machines/w32processes/0000DQQEE.parquet')
   w32processes_memorysections_dataset = pq.ParquetDataset('C:/Users/bboyz/OneDrive/Desktop/MCSI Remote Cybersecurity Internship/Threat Hunting/mcsithreathunting2machines/w32processesmemorysections/0000DQQEE.parquet')
   w32services_dataset = pq.ParquetDataset('C:/Users/bboyz/OneDrive/Desktop/MCSI Remote Cybersecurity Internship/Threat Hunting/mcsithreathunting2machines/w32services/0000DQQEE.parquet')
   w32tasks_dataset = pq.ParquetDataset('C:/Users/bboyz/OneDrive/Desktop/MCSI Remote Cybersecurity Internship/Threat Hunting/mcsithreathunting2machines/w32tasks/0000DQQEE.parquet')
   
   # convert dataset into pandas
   domainusers = domainusers_dataset.read().to_pandas()
   loggedonusers = loggedonusers_dataset.read().to_pandas()
   useraccounts = useraccounts_dataset.read().to_pandas()
   w32drivers = w32drivers_dataset.read().to_pandas()
   w32persistence_fileitems = w32persistence_fileitems_dataset.read().to_pandas()
   w32persistence_registryitems = w32persistence_registryitems_dataset.read().to_pandas()
   w32persistence_servicesitems = w32persistence_servicesitems_dataset.read().to_pandas()
   w32processes = w32processes_dataset.read().to_pandas()
   w32processes_memorysections = w32processes_memorysections_dataset.read().to_pandas()
   w32services = w32services_dataset.read().to_pandas()
   w32tasks = w32tasks_dataset.read().to_pandas()
   ```

3. Perform a filter for suspicious drivers for both machines 0000DQQEE and 0001LXQEN
   ```
   # Filter for suspicious drivers
   suspicious_drivers_modulename = w32drivers[
       (w32drivers['modulename'].str.contains(r'(?:debug|hook|dump|malware|rootkit)', na=False, case=False))  # Driver names suggesting malicious behavior
   ]
   
   print("Suspicious Drivers Module Names:")
   print(suspicious_drivers_modulename)
   ```
   Based on the given datasets, both machines will give the same results <br/>
   ![image](https://github.com/user-attachments/assets/4639dddb-dffc-462e-b744-7a759a119aae)
4. Then filter for suspicious processes in machine 0000DQQEE
   ```
   # List of suspicious executables
   suspicious_executables = r'(?:narrator\.exe|sethc\.exe|utilman\.exe|osk\.exe|searchui\.exe|magnify\.exe|calculator\.exe)'
   
   # Filter rows in w32processes dataset
   suspicious_processes = w32processes[
       w32processes['name'].str.contains(suspicious_executables, na=False, case=False)
   ]
   
   print("Suspicious Processes:")
   print(suspicious_processes)
   ```
   Take note of the process names and the corresponding usernames <br/>
   ![image](https://github.com/user-attachments/assets/6fa89c69-c676-4aec-8f54-270b86e9cee4)
5. Check the processes for malicious activities using the given suspicious terms
   ```
   # List of suspicious terms
   suspicious_terms_processes = r'(?:tasklist|ipconfig|systeminfo|net|query|wmic|sc|rundll32|Powershell|mshta|netstat)'
   
   # Filter rows in w32processes dataset
   suspicious_processes = w32processes[
       w32processes.apply(
           lambda row: row.astype(str).str.contains(suspicious_terms_processes, na=False, case=False).any(),
           axis=1
       )
   ]
   
   # Print suspicious processes
   print("Suspicious Processes:")
   print(suspicious_processes)
   ```
   Note that a number of suspicious processes involving credential harvesting and net.exe can be observed in machine 0000DQQEE <br/>
   ![image](https://github.com/user-attachments/assets/e2de1a7c-92a7-4b91-88b9-b9bea9fe280e)




