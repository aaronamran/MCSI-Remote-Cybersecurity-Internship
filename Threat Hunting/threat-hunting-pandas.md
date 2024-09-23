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
#### Installation and Preparing Sample Dataset
1. Download and install [Redline](https://fireeye.market/apps/211364) software from FireEye Market
2. Open PowerShell with administrative privileges
3. Download and install the classic [Jupyter Notebook](https://jupyter.org/install) by typing `pip install notebook` 
4. Download and install lxml, pandas and pyarrow by typing `pip install lxml pandas pyarrow`
5. Open Redline and in `Collect Data options`, click `Create a Standard Collector`
6. Choose a target platform, then click `Edit your script`. A simple digital forensic extraction can only involve `Process Listing`, and disabling `Drivers Enumeration` and `Hook Detection` and click `OK`
7. Browse a folder to save the collector to, and click `OK`
8. In the directory where the collector is saved to, run the RunRedLineAudit.bat file, as seen in the screenshot below ![image](https://github.com/user-attachments/assets/ffbd06c5-5fdb-4e6b-bcc9-558e4f24998c)
   This will create a Sessions folder, which has an Audits folder that stores newly created XML files containing recorded data
9. To convert the XML files into Parquet files for data manipulation in Jupyter Notebook, use this [online tool](https://dataconverter.io/convert/xml-to-parquet/) by DataConverter.io, and then download the Apache Parquet file
10. Start Jupyter Notebook by entering the command `jupyter notebook`. It will return a localhost link to be opened in the web browser
11. To load the generated Parquet file, select New > Python 3 at the top right area as seen below
    ![image](https://github.com/user-attachments/assets/b9afc7fe-e761-4fae-8841-37974978a5fc)
12. In the new `.ipynb` file, the following code is used, and the comments are to be noted:
    ```
    # MRCI - Threat Hunting with Pandas

    # import dependencies
    import pandas as pd
    import pyarrow as pa
    import pyarrow.parquet as pq
    
    # convert Parquet file into a dataset
    # change backslashes in copied file path to forward slashes to prevent Unicode escape sequence errors 
    processes_dataset = pq.ParquetDataset('C:/Users/bboyz/Downloads/redlineauditsample.parquet')
    
    # convert dataset into pandas
    w32processes = processes_dataset.read().to_pandas()
    ```
13. Pressing Shift + Enter on the keyboard runs the current cell operation and moves to a new cell
14. Enter `w32processes` and the following output (which displays the first five rows and last five rows) is seen:
    ![image](https://github.com/user-attachments/assets/ef221076-49da-4b87-bbf1-9bd224a69afe)
15. To undo cell operation after facing error, right-click on cell and clear cell output and undo cell operation

#### Basic Data Manipulation
1. Searching for values
   ```
   w32processes[column].str.contains('value', na=False)
   ```
   Example:
   ```
   # search for rows where the process name contains 'xagt'
   search_results = w32processes[w32processes['name'].str.contains('xagt', na=False)]
   print(search_results)
   ```
2. Sorting data
   ```
   w32processes.sort_values(by='column', ascending=False)
   ```
   Example:
   ```
   # sort by PID in descending order
   sorted_processes = w32processes.sort_values(by='pid', ascending=False)
   print(sorted_processes)
   ```
3. Selecting specific columns
   ```
   w32processes[['col1', 'col2']]
   ```
   Example:
   ```
   # selecting specific columns
   selected_columns = w32processes[['name', 'SecurityID', 'SecurityType']]
   print(selected_columns)
   ```
4. Filtering specific data elements
   ```
   w32processes[condition]
   ```
   Example:
   ```
   # filtering specific process
   filtered_processes = w32processes[w32processes['name'] == 'prevhost.exe']
   print(filtered_processes)
   ```
