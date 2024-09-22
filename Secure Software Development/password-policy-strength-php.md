# Write A Web Application That Enforces A Strong Password Policy And Displays A Password Strength Meter
A password strength meter helps ensure secure passwords by indicating their strength and offering tips to improve them, making passwords harder to hack and less likely to be compromised.

## References
- [OWASP - Authentication Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md) by OWASP
- [OWASP - OWASP Passfault](https://www.owasp.org/index.php/OWASP_Passfault) by OWASP

## Web Application Requirements
- Registration, login, and password update pages
- A password policy requiring a minimum of 10 characters
- A password strength meter on the registration and password update pages
- The password strength meter must visually indicate the strength of the password (e.g., weak, moderate, strong)
- Provide users with an estimation of the time it would take for an adversary to crack the selected password

## Benchmarks
- Register a new account using a variety of passwords with varying levels of complexity (weak, moderate, strong)
- Observe how the password strength meter accurately assesses the strength of the passwords
- Verify that the application enforces the password policy of a minimum of 10 characters
- Note the estimated time provided for an adversary to crack each password
