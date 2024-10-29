# Write A Web Application That Provides A Secure Login Form
A website's login form is crucial for account access and must be secure to protect user data. Secure forms use HTTPS and verify credentials before granting access.


## References
- [OWASP - Authentication Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md) by OWASP
- [10,000 most common passwords](https://en.wikipedia.org/wiki/Wikipedia:10,000_most_common_passwords) by Wikipedia

## Web Application Requirements
- Employ SHA256 encryption for password storage to enhance security
- Apply the 'Secure' and 'HttpOnly' flags to all session cookies, bolstering their protection
- Implement an account lockout mechanism that triggers after 5 failed login attempts
- Restrict usernames to alphanumeric characters only, disallowing special characters
- Enforce a robust password policy mandating a minimum of 12 characters, including letters, numbers, special characters, and a mix of uppercase and lowercase characters
- Blacklist the top 100 most common passwords to deter their use
- Deploy the web application using HTTPS for added security

## Benchmarks
- Access the deployed web application and demonstrate the secure login process over HTTPS
- Attempt to log in with an incorrect password multiple times to trigger the account lockout mechanism
- Show that session cookies possess the 'Secure' and 'HttpOnly' flags using browser developer tools
- Register a new account and showcase the enforcement of the stringent password policy
- Attempt to use common passwords and verify their prohibition due to the password blacklist

## Tasks
- Demonstrate successful login with proper credentials
- Trigger and display the account lockout mechanism after consecutive failed login attempts
- Utilize browser tools to validate the presence of 'Secure' and 'HttpOnly' flags on session cookies
- Showcase the enforcement of the comprehensive password policy during registration
- Exhibit the prevention of using common passwords due to the blacklist
- Emphasize the secure deployment over HTTPS for data protection


## Solutions With Scripts
- [Link to the folder of scripts](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/tree/main/Secure%20Software%20Development/scripts/secure-login-form)
- If a self-signed SSL certificate is not yet created, follow the steps in [this task](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Secure%20Software%20Development/secure-cookie-flag-php.md)

1. Start XAMPP and ensure that Apache and MySQL services are running. In phpMyAdmin, go to the Databases tab. Enter the name 'secure_login' in the Create database field and click Create.
2. Set up the database by creating a `users` table with columns `id`, `username`, `password`, `failed_attempts` and `lock_time` by pasting the following SQL query into the query editor
   ```
   CREATE TABLE users (
     id INT AUTO_INCREMENT PRIMARY KEY,
     username VARCHAR(50) NOT NULL UNIQUE,
     password CHAR(64) NOT NULL,
     failed_attempts INT DEFAULT 0,
     lock_time TIMESTAMP NULL DEFAULT NULL
   );
   ```
3. In the XAMPP htdocs directory, create a folder called 'secure_login' and add the following files: `register.php`, `login.php`, `logout.php`, `config.php`, `functions.php`
4. Open a web browser and navigate to localhost. Access the web application and login with the correct credentials (username: localhoster, password: Str0ng!Passw0rd@1)
5. Emphasize the secure deployment over HTTPS for data protection
6. Use the browser tools to show 'Secure' and 'HttpOnly' flags on the session cookies
7. After logging out, create a new account and showcase the strong password policy by using common (top 100) passwords
8. Trigger the account lockout mechanism by attempting 5 failed logins, by intentionally using the wrong password
9. 

