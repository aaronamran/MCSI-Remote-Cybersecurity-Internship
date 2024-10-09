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


## Solutions With Scripts
[Here is the link to the folder of scripts](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/tree/main/Secure%20Software%20Development/scripts/secure-cookie-flag)
1. Before starting the PHP Session on localhost in XAMPP, HTTPS needs to be set up by configuring Apache to use SSL with a self-signed certificate
2. Enable OpenSSL in XAMPP by navigating to XAMPP's configuration directory
   ```
   sudo nano /opt/lampp/etc/httpd.conf
   ```
3. Look for the following lines and make sure they are not commented out. Remove the # if necessary
   ```
   LoadModule ssl_module modules/mod_ssl.so
   Include etc/extra/httpd-ssl.conf
   ```
4. Generate a self-signed SSL certificate using each of the following commands in order
   ```
   cd /opt/lampp
   sudo mkdir ssl
   cd ssl
   ```
5. Now generate a self-signed SSL certificate using OpenSSL. During the certificate generation process, you will be asked to enter details such as your country, state, and common name (you can leave most of them blank, but use localhost for the Common Name (CN))
   ```
   sudo openssl req -new -x509 -days 365 -nodes -out server.crt -keyout server.key
   ```
6. Configure Apache for SSL. Edit the Apache SSL configuration file (httpd-ssl.conf) to use the newly generated certificate
   ```
   sudo nano /opt/lampp/etc/extra/httpd-ssl.conf
   ```
7. Look for the following lines and update them to point to your self-signed certificate
   ```
   # SSL certificate file
   SSLCertificateFile "/opt/lampp/ssl/server.crt"
   # SSL certificate key file
   SSLCertificateKeyFile "/opt/lampp/ssl/server.key"
   ```
8. Update the VirtualHost to use HTTPS: In the same file (httpd-ssl.conf), update or add the <VirtualHost> section to handle HTTPS requests on localhost
   ```
   <VirtualHost _default_:443>
      DocumentRoot "/opt/lampp/htdocs"
      ServerName localhost:443
      SSLEngine on
      SSLCertificateFile "/opt/lampp/ssl/server.crt"
      SSLCertificateKeyFile "/opt/lampp/ssl/server.key"
      <Directory "/opt/lampp/htdocs">
          Options Indexes FollowSymLinks
          AllowOverride All
          Require all granted
      </Directory>
   </VirtualHost>
   ```
9. Allow HTTP and HTTPS Ports in Kali Firewall (Optional): If you're running a firewall on Kali, make sure ports 80 (HTTP) and 443 (HTTPS) are allowed
    ```
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    ```
10. Restart Apache to Apply Changes: After making these changes, restart Apache to apply the SSL configuration
    ```
    sudo /opt/lampp/lampp restart
    ```
11. The site can now be accessed using the URL that has https in it
12. When the web application is running, login to it. Open the browser's developer tools and navigate to the "Application" or "Storage" tab. Under cookies, verifu the session cookie has the "Secure" flag enabled, meaning it is only sent over HTTPS

