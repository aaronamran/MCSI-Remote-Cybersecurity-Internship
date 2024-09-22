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

## Steps with Solutions
1. Create the main application file
   ```
    <?php
    // Setting the X-Frame-Options header
    header('X-Frame-Options: DENY');
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Clickjacking Prevention App</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                text-align: center;
                padding: 50px;
            }
        </style>
        <script>
            // Detect if the page is loaded in an iframe
            if (window.top !== window.self) {
                alert('This application cannot be loaded in an iframe.');
                window.top.location = window.self.location; // Redirect to break out of iframe
            }
        </script>
    </head>
    <body>
        <h1>Welcome to the Secure Web Application!</h1>
        <p>This application is protected against clickjacking.</p>
    </body>
    </html>
   ```
2. Create the test file
   ```
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Clickjack Test</title>
    </head>
    <body>
        <h1>Clickjack Test</h1>
        <iframe src="http://localhost/index.php" width="600" height="400"></iframe>
    </body>
    </html>
   ```
3. Configure web server. Ensure XAMPP is running, and save `index.php` and `clickjacktest.php` in a subdirectory (preventclickjackingapp) within the `htdocs` directory
4. Access the web application by going to `http://localhost/preventclickjackingapp/` in a web browser
5. Check the header by using developer tools (F12) to inspect the response headers. Confirm that `X-Frame-Options` is set to `DENY`
6. Test clickjacking by navigating to `http://localhost/preventclickjackingapp/clickjacktest.php`. You should see an alert message indicating that the application cannot be loaded in an iframe
