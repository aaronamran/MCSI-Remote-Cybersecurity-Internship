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


## Solutions With Scripts
- [Link to the folder of scripts](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/tree/main/Secure%20Software%20Development/scripts/password-strength-meter)
1. Start XAMPP and ensure that Apache and MySQL services are running. Since the main goal of this task is to showcase password strength policy, using a database to store user credentials is not needed
2. In the XAMPP htdocs directory, create a folder called 'pwdstrength' and add the following file: `index.php`, `password_strength.js`, `process_registration.php`, `register.php` and `style.css`
3. Open a web browser and navigate to localhost. Access the web application and register a new account with a username and password of any strength
4. Test different levels of password in the password field. For example, use `abcdefg` as a weak test password and click Register. The following will be seen
   ![image](https://github.com/user-attachments/assets/7af027e7-ac6c-4514-af87-b09cbc9d8d9b)
5. The password `Password123` which is considered a moderate strength password will display the following
   ![image](https://github.com/user-attachments/assets/2364b284-501b-4eab-833a-3b00735b482d)
6. A strong password like `7qL$1jH#4gP2z@` will show the following
   ![image](https://github.com/user-attachments/assets/278053a8-f533-4391-a72b-f0443a0ec5d9)



