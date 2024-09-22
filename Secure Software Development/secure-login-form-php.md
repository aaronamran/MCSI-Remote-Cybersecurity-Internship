# Write A Web Application That Provides A Secure Login Form
A website's login form is crucial for account access and must be secure to protect user data. Secure forms use HTTPS and verify credentials before granting access.


## References
- [OWASP - Authentication Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md) by OWASP

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
Emphasize the secure deployment over HTTPS for data protection
