# Lab Setup: Threat Hunting With Pandas
Threat hunting is the proactive search for threats to an organization's security. Using Python pandas, analysts can detect suspicious patterns in data such as logs, network traffic, and endpoints. This helps identify and address potential threats before they cause harm.

## References
- [Pandas - Python Data Analysis Library](https://pandas.pydata.org/) by pandas
- [Apache - Reading and Writing the Apache Parquet Format](https://arrow.apache.org/docs/python/parquet.html) by Apache Arrow
- [Jupyter Project - Jupyter Notebook](https://jupyter.org/) by Jupyter


## Tasks
- Install Python (version >= 3.6)
- Install required Python libraries: Pyarrow, Pandas, Jupyter Notebook
- Load a sample Parquet dataset into a pandas DataFrame and display its contents
- Perform basic data manipulation tasks using pandas, such as filtering or searching for specific data elements within the DataFrame

## Steps With Solutions
1. Download and install [Redline](https://fireeye.market/apps/211364) software from FireEye Market
2. Open PowerShell with administrative privileges
3. Download and install the classic [Jupyter Notebook](https://jupyter.org/install) by typing `pip install notebook` 
4. Download and install pandas and pyarrow by typing `pip install pandas pyarrow`
5. Open Redline and in `Collect Data options`, click `Create a Standard Collector`
6. Choose a target platform, then click `Edit your script`. A simple digital forensic extraction can only involve `Process Listing`, and disabling `Drivers Enumeration` and `Hook Detection` and click `OK`
7. Browse a folder to save the collector to, and click `OK`
8. In the directory where the collector is saved to, run the RunRedLineAudit.bat file, as seen in the screenshot below ![image](https://github.com/user-attachments/assets/ffbd06c5-5fdb-4e6b-bcc9-558e4f24998c)

9. Start Jupyter Notebook by entering the command `jupyter notebook`. It will return a localhost link to be opened in the web browser
10. 
