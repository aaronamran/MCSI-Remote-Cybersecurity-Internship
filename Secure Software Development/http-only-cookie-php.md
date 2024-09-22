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
