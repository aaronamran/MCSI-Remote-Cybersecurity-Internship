# Write A Web Application That Detects And Blocks Brute Force Attacks
Detecting brute force attacks is important because it can help you protect your systems and data from being compromised. Brute force attacks can be very costly and damaging, so it's important to be prepared and take steps to protect your systems. The three most common types of brute force attacks are:
- Horizontal: the attacker attempts several passwords against a single account
- Vertical: the attacker attempts a single password against multiple accounts
- Mixed: The attacker attempts 2 to 5 passwords against multiple accounts


## References
- [Authentication Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md) by OWASP on GitHub
- [Testing for Brute Force (OWASP-AT-004)](https://wiki.owasp.org/index.php/Testing_for_Brute_Force_(OWASP-AT-004)) by OWASP


## Tasks
- Create a web application with the following features:
  - An authentication mechanism (e.g., username and password) to allow users to log in
  - At least 300 user accounts identified by sequential numbers (e.g., 0001, 0002, 0003, etc.)
- Implement a mechanism that detects each of the attacks listed below. After detecting such behavior, temporarily block further login attempts for the specific account(s)
- Launch the following attacks
  - Horizontal brute force attacks
  - Vertical brute force attacks
  - Mixed brute force attacks
  - Account lockout policy abuses
  - Slowed-paced brute force attacks
 

## Benchmarks
- Present the login page of the web application and provide an overview of its authentication mechanism
- Perform a horizontal brute force attack against a user account, showcasing how the application detects and responds to the attack by blocking further login attempts
- Conduct a vertical brute force attack, demonstrating the application's capability to identify and block unauthorized access attempts
- Execute a mixed brute force attack against multiple user accounts, and show how the application detects and implements temporary blocks for the targeted accounts
- Attempt an account lockout policy abuse and showcase how the application mitigates the abuse
- Demonstrate a slow-paced brute force attack (one attempt per minute), and validate the application's ability to detect and block such attempts


## Practical Approach
[Link to the folder of scripts](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/tree/main/Secure%20Software%20Development/scripts/block-brute-force-attacks) 
<br/>
1. Create the files needed and host it locally on XAMPP
2. Create a database in phpMyAdmin called `block_brute_force` and populate it using `setup.php` by clicking `Setup Database and Populate Users` <br/>
   ![image](https://github.com/user-attachments/assets/44d120e0-3fdc-443c-9a1f-c30abad32273) <br/>
   Then modify some of the passwords so that it contains several passwords from `passwords.txt` file <br/>
   ![image](https://github.com/user-attachments/assets/058e7fdb-c386-48d8-9f06-a1927a921ec6)

3. Login to a known account using the correct username and password <br/>
   ![image](https://github.com/user-attachments/assets/f7d141ab-25ed-4887-9fc7-11d84981a357) <br/>
   Reset the login attempts in `setup.php` <br/>
   ![image](https://github.com/user-attachments/assets/28c6a3f0-e16f-4ce9-a7de-52a6834ed3c5)

4. Perform a horizontal brute force attack against a user account. Since 300 users is alot, input only few of the users for Proof of Concept (PoC) <br/>
   ![image](https://github.com/user-attachments/assets/826544de-fa43-4bee-96d4-893f89b29e38) <br/>
   After completion, reset the login attempts in `setup.php`
5. Then conduct a vertical brute force attack against a single user <br/>
   ![image](https://github.com/user-attachments/assets/2557c8d7-ba16-41fc-9818-c254bebb8622) <br/>
   After completion, reset the login attempts in `setup.php`
6. Execute a mixed brute force attack against multiple user accounts <br/>
   ![image](https://github.com/user-attachments/assets/07914e48-0278-49ad-94cf-70158cb5436d) <br/>
   After completion, reset the login attempts in `setup.php`
7. To demonstrate a slow-paced brute force attack, just attack a single account for PoC <br/>
   ![image](https://github.com/user-attachments/assets/d6acaef5-6e46-47d9-8cd9-2289b3f2efb6)

