# Write A Web Application That Correctly Utilizes The Secure Cookie Flag
To enhance HTTP security, enable the secure cookie flag. This ensures cookies are encrypted during transmission, protecting them from interception. Without this flag, cookies are sent in clear text and can be easily stolen.

## References
- [OWASP - SecureFlag](https://owasp.org/www-community/controls/SecureCookieAttribute) by OWASP

## Web Application Requirements
- Authentication functionality to allow users to log in securely
- Deployed over SSL
- Upon successful authentication, generates a session token for the user
- Stores the session token securely in the user's cookies
- The session id cookie is configured to have the Secure flag set

## Tasks
- Access the web application via the https protocol and showcase its authentication page
- Log in as a user and demonstrate that a session token is stored in the user's cookies
- Use the web developer tools to inspect the cookies and emphasize that the session id cookie has the Secure flag set

## Benchmarks
- Host the web application on a web server with a valid SSL certificate
- Access the web application through a web browser
- Use the web developer tools to inspect the cookies set by the application
- Confirm that the session id cookie has the Secure flag turned on, indicating that it is only transmitted over HTTPS connections
