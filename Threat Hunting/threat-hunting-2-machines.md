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
[Link to comprehensive PDF report]() <br/>
1. To investigate the given attacks in the dataset, it is essential to know the specific indicators of compromise (IoCs) or behaviors associated with each attack
2. Prepare the Jupyter Notebook and in the first cell, use the following code to import libraries and declare variables
   ```
   # MRCI Threat Hunting - Perform Threat Hunting On 2 Machines

   # import dependencies
   import pandas as pd
   import pyarrow as pa
   import pyarrow.parquet as pq
   
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

3. Regarding Malicious Windows Commands, look for suspicious commands executed by users or processes, often seen in:
   - Task Scheduler commands (`schtasks.exe`)
   - Command Prompt commands (`cmd.exe`)
   - PowerShell commands (`powershell.exe`)
   - Tools like `net.exe`, `net1.exe`, `wmic.exe`, `reg.exe`, etc
   Focus on datasets like `w32processes` and `w32tasks`. Review command lines for keywords like `add`, `delete`, or execution of `.bat` or `.ps1` files from non-standard directories like `%Temp%` or `%AppData%`. To filter out suspicious activities in `w32processes`, use
   ```
   malicious_commands = w32processes[w32processes['arguments'].str.contains(
      r'(?:cmd\.exe|powershell\.exe|schtasks\.exe|wmic\.exe|net\.exe|reg\.exe)', na=False, case=False
   )]
   print(malicious_commands)
   ```
   ![image](https://github.com/user-attachments/assets/61a7627a-cbfe-4511-b74a-268d6f20ad92)

   To filter out suspicious activities in `w32tasks`, the criteria for filtering suspicious activities are as the following:
   - Unverified Signatures: `signatureverified == False` or `signatureexists == False`. Tasks with unsigned or unverified executables are suspicious
   - Executable Paths: Check `execprogrampath` for unusual locations (e.g., `C:\Windows\Temp`, `AppData`, etc.). Suspicious tasks often run executables outside of trusted directories
   - Execution Arguments: Use similar patterns as you did for `arguments` in `w32processes`. Look for commands like `cmd.exe`, `powershell.exe`, `reg.exe`, etc., in the `execarguments` field
   - Account Types: `accountrunlevel == SYSTEM` or privileged accounts running tasks that seem out of the ordinary.
   - Task Creators: Check the `creator` column for unknown or non-standard creators.
   ```
   # Ensure boolean columns for signatureverified and signatureexists
   w32tasks['signatureverified'] = w32tasks['signatureverified'].str.lower() == "true"
   w32tasks['signatureexists'] = w32tasks['signatureexists'].str.lower() == "true"
   
   # Filter for suspicious tasks
   suspicious_tasks = w32tasks[
       (~w32tasks['signatureverified']) |  # Unverified signatures
       (~w32tasks['signatureexists']) |    # Missing signatures
       (w32tasks['execprogrampath'].str.contains(r'(?:temp|AppData|ProgramData)', na=False, case=False)) |  # Unusual paths
       (w32tasks['execarguments'].str.contains(r'(?:cmd\.exe|powershell\.exe|schtasks\.exe|wmic\.exe|reg\.exe)', na=False, case=False)) |  # Suspicious commands
       (w32tasks['accountrunlevel'].str.contains(r'(?:SYSTEM|Administrator)', na=False, case=False))  # Privileged accounts
   ]
   
   print(suspicious_tasks)
   ```
   ![image](https://github.com/user-attachments/assets/42ae00b7-3209-46d8-bba5-987362f43c5a) <br/>
   ![image](https://github.com/user-attachments/assets/133cb4fb-1a9b-41bc-a486-a49ceb1bda8f)
4. For the attack Using Accessibility Features for Persistence, attackers often replace accessibility tools like `sethc.ex` (Sticky Keys) to gain persistence. Focus on datasets like `w32persistence_fileitems` or `w32drivers`. Search for renamed or modified accessibility tools (`sethc.exe`, `utilman.exe`) and look for new file paths or unexpected replacements
5. In terms of Modifying a Windows Service, attackers can modify existing services to gain persistence by changing configurations or binary paths. Focus on datasets like `w32persistence_servicesitems` and `w32services`. Search for suspicious `service_name` or modified `image_path`. Investigate services with unexpected binary paths or descriptions
6. A Path Interception attack means attackers may place malicious executables in directories higher in the PATH environment variable order. Focus on datasets like `w32persistence_fileitems` and `w32drivers`. Search for files in common directories, e.g., `C:\Windows\Temp\`, `C:\Users\Public\`, or paths with missing quotes (e.g., "C:\Program Files\malware.exe" instead of "C:\Program Files\ Legit App\legit.exe"). Check for `.exe` or `.dll` files placed in these directories
7. Process Injection attack is performed by attackers injecting malicious code into legitimate processes like `explorer.exe` or `svchost.exe`. Focus on datasets like `w32processes` and `w32processes_memorysections`. Search for memory sections marked as writable and executable (`RWX` permissions). Suspicious processes like `svchost.exe`, `explorer.exe`, `notepad.exe`, etc
8. 




