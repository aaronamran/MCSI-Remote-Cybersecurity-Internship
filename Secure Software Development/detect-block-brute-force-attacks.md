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
- Demonstrate a slowed-paced brute force attack (one attempt per minute), and validate the application's ability to detect and block such attempts


## Practical Approach
[Link to the folder of scripts]()
1. 
