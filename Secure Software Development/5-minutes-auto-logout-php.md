# Write A Web Application That Automatically Logs Out Users After 5 Minutes Of Inactivity
Securing user sessions is vital in web development. Allowing idle sessions can lead to security risks, like token reuse or unauthorized access. Automatic logout after inactivity helps protect user accounts and sensitive data, reducing the risk of session-related attacks.

## References
- [OWASP - Session Timeout](https://www.owasp.org/index.php/Session_Timeout) by OWASP

## Web Application Requirements
- An authentication mechanism (e.g., username and password) to allow users to log in
- Use JavaScript or a server-side language (e.g., PHP or Node.js) to manage user sessions
- Upon successful authentication, generate a session token and store it in a secure HTTP cookie
- Set the expiration time for the session token to 5 minutes from the last user activity

## Benchmarks
- Host the web application on a web server
- Authenticate into the application using valid credentials
- After successful authentication, wait for 5 minutes without any user activity
- Confirm that the web application automatically logs you out after the 5-minute inactivity period
- Attempt to access protected resources or perform actions that require authentication after being logged out to ensure proper security measures are enforced

## Solutions with Scripts
- [Link to the folder of scripts for the web application](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/tree/main/Secure%20Software%20Development/scripts/5mins-autologout)
- 
