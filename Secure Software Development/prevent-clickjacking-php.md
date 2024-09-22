# Write A Web Application That Prevents Clickjacking
A clickjacking vulnerability occurs when an invisible frame is placed over a website, tricking users into clicking it, potentially stealing data or installing malware. The X-Frame-Options HTTP header helps prevent this by controlling whether a page can be framed. Setting it to "DENY" blocks all framing, while "SAMEORIGIN" allows framing only from the same domain.

## References
- [OWASP - Testing for Clickjacking](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/09-Testing_for_Clickjacking) by OWASP


## Tasks
- Develop a web application using HTML, CSS, and JavaScript
- Implement JavaScript code to detect when the web application is loaded inside an iframe
- Configure the web server to return the X-Frame-Options HTTP header with the appropriate settings to prevent clickjacking
- Create a separate "clickjack test" HTML file that contains an iframe element attempting to load your web application
  
## Benchmarks
- Host the web application on a web server
- Demonstrate that legitimate users can interact with your web application without any hindrance
- Use your browsers developer tools to verify that the X-Frame-Options HTTP header is correctly set
- Open your clickjack test HTML file and verify that your web application cannot be loaded within an iframe
