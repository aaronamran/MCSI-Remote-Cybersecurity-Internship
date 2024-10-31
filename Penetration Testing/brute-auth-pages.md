# Write A Tool To Brute Authentication Pages
Guessing credentials remains one of the easiest ways to escalate privileges in systems. Brute force tools are key in security testing, as they help identify weak passwords and vulnerabilities by rapidly trying multiple combinations. These tools also test the strength of passwords and other security measures, uncovering weaknesses that might otherwise be missed

## References
- [Cross-Site Request Forgery Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md) by OWASP on GitHub

## Tasks
- Create a vulnerable web application that includes the following:
  - A login form that validates user credentials
  - 1000 user accounts with sequential usernames (e.g., 1, 2, 3, etc.)
  - Some of these accounts must have weak passwords configured to simulate vulnerable accounts
  - Cross-Site Request Forgery (CSRF) protection in the login form
- Create a brute force tool that has the following:
  - Accepts a custom list of usernames
  - Accepts a custom list of passwords
  - Can vertically brute force user accounts
  - Can horizontally brute force user accounts
  - Handles and bypasses the CSRF protection
  

## Benchmarks
- Ensure that a random CSRF token is generated and submitted with each login request
- The tool can handle and bypass the CSRF protection
- The tool can perform vertical brute force attacks to guess passwords for multiple user accounts
- The tool can perform horizontal brute force attacks to guess passwords for a single user account with different password combinations


## Solutions With Scripts
[Link to the folder of scripts]
1. 
