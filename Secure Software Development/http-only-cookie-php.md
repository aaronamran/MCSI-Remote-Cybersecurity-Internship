# Write A Web Application That Correctly Utilizes The HTTP Only Cookie Flag
HttpOnly is a flag in the Set-Cookie HTTP response header that helps protect session cookies from client-side scripts. Without it, anyone with browser access could read the session cookie, potentially exposing sensitive data like passwords.

## References
- [OWASP - HttpOnly](https://www.owasp.org/index.php/HttpOnly) by OWASP

## Web Application Requirements
- An authentication mechanism (e.g., username and password) to allow users to log in
- Use JavaScript or a server-side language (e.g., PHP or Node.js) to manage user sessions
- Upon successful authentication, generate a session token and store it in an HTTP cookie
- Ensure that the session cookie is configured with the HTTPOnly flag enabled


## Benchmarks
- Host the web application on a web server
- Authenticate into the application using valid credentials
- After successful authentication, use the web developer tools of your browser to inspect cookies
- Confirm that the session ID cookie contains the HTTPOnly flag, indicating that it cannot be accessed by client-side scripts

## Tasks
- Interact with the web application's authentication page and showcase the login process
- Use the browser's web developer tools to view the cookies associated with the web application

## Solutions With Scripts
[Link to the folder of scripts for the web application](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/tree/main/Secure%20Software%20Development/scripts/httponly-cookie)

1. Open the web application in a web browser. Open the Developer Tools and navigate to Cookies. Before logging in to the web application, the HTTP Only cookie flag's value should be "false"
2. Once logging in to the web application, the HTTP Only cookie flag will now be "true"
