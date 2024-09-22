# Write An Application Vulnerable To Arbitrary Command Execution
An arbitrary command execution vulnerability occurs when a web application executes user-supplied commands, often through unsafe APIs like `system()`, `shell_exec()`, or `exec()`. This critical flaw allows attackers to inject commands, potentially gaining unauthorized access or full control of the server. Understanding how these vulnerabilities are exploited highlights the importance of input validation and sanitization in securing web applications, helping developers prevent serious security breaches.

## References
- [OWASP - Command Injection](https://www.owasp.org/index.php/Command_Injection) by OWASP
- [Wikipedia - Arbitrary Code Execution](https://en.wikipedia.org/wiki/Arbitrary_code_execution) by Wikipedia

## Tasks
- Use a Linux VM to host the vulnerable web application
- Select and install a web server on the Linux VM
- Develop a simple web application with the functionality to accept user input to perform a task
- Ensure the application is realistic and incorporate styling and layout features
- The vulnerability is that this user input field does not perform any input validation or sanitization
- Host the vulnerable web application on the server and access it
- Research how you can inject commands into the text field of a web application
- Use the text field to inject commands as input to the web application
- Inject at least (3) commands and retrieve information about the server hosting the web application

## Benchmarks
- Validate that your web application has the functionality to accept user input and display relevant output
- Validate that you can inject commands as arbitrary input to the vulnerable web application
- Validate that you can view information about the server hosting the web application
- Show the vulnerable web application with the intended functionality
- Show the results of arbitrary command execution on the vulnerable web application
- Show that the three commands injected into the application provide information about the hosting server

