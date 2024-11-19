# Write A Web Application That Detects And Safely Handles Crashes And Exceptions
Properly handling crashes and exceptions is crucial in software development, as these issues can create security vulnerabilities. Adversaries often exploit software crashes to expose error messages and stack traces, revealing internal application details and enabling them to execute malicious code. To mitigate this risk, web applications must safely manage error messages and stack traces by concealing them from potential attackers while alerting developers to critical bugs.

## References
- [Testing for Stack Traces](https://www.owasp.org/index.php/Testing_for_Stack_Traces_(OTG-ERR-002)) by OWASP


## Tasks
- Create a web application with the following vulnerabilities:
  - A user input that is vulnerable to SQL injection
  - A user input that is vulnerable to command injection
- Implement error handling mechanisms in the web application using JavaScript
- Catch any errors or exceptions that may occur during user interactions or data processing
- Set up a server-side script to handle error logging
- When an error occurs, use the server-side script to write the error details to a log file
- Ensure that the log file is securely stored and not accessible to the public
- Instead of showing detailed error messages or stack traces to users, create a generic error message to inform them that an error occurred

## Benchmarks
- Exploit the web application using SQL injection
- Exploit the web application using command injection
- The web application detects and handles all errors gracefully by catching exceptions and preventing detailed error messages from being shown to users
- The generic message does not reveal sensitive information about the application's internals
- Access the log file (via server-side script) to demonstrate the logged errors without sensitive information exposure
- Use a fuzzer tool to fuzz vulnerable inputs and confirm that the web application's error handling remains robust and secure


## Solutions With Scripts

- [Link to the folder of scripts](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/tree/main/Secure%20Software%20Development/scripts/handle-crashes-exception)

1. Start XAMPP and ensure that Apache and MySQL services are running
2. In the XAMPPP htdocs directory, create a folder called 'handleerrors' and add the following files: `index.php` and `error_handler.php`
3. Access phpMyAdmin at `http://localhost/phpmyadmin`. To create a new database and populate it, run the following SQL queries
   ```
    CREATE DATABASE vulnerable_app;

    USE vulnerable_app;
    
    CREATE TABLE users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50),
        password VARCHAR(50)
    );
    
    INSERT INTO users (username, password) VALUES
    ('admin', 'password123'),
    ('test_user', 'test123');
   ```
4. Open a web browser and navigate to localhost. Access the web application and try the following SQL injections:
   - Add `?user_id=1 OR 1=1` to the end of the URL. This would retrieve all rows because 1=1 is always true
   - 
5. To test command injections, input the following commands: `ls`, `whoami`. These inputs can be exploited by appending malicious commands such as `; cat /etc/passwd`
6. To fuzz with Burp Suite, capture the SQL injection request (e.g., `http://localhost/vulnerable_app/?user_id=1`) and send the request to the Intruder. Configure payloads for the `user_id` parameter: 
   - Payload set for fuzzing SQL injection:
     - `' OR 1=1--`
     - `1 UNION SELECT NULL, username FROM users--`
     - `' AND SLEEP(5)--`
     <br/>
     Start the attack and analyze server responses for successful injections
   - Payload set for fuzzing command injection:
     - `; ls`
     - `; whoami`
     - `; cat /etc/passwd`
7. Expected example of logged error in `logs/errors.log` handled by custom error handler:
   `[2024-11-19 12:00:00] Error: SQL syntax error in /opt/lampp/htdocs/vulnerable_app/index.php on line 20`



