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
