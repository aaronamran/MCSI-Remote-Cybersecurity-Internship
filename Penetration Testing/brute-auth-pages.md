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


## Practical Approach
- [Link to the folder of scripts](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/tree/main/Penetration%20Testing/scripts/brute-auth-pages) <br/>

1. Start XAMPP and ensure that Apache and MySQL services are running. In the XAMPP htdocs directory, create a folder called 'bruteauth' and add the following files: `setup.php`, `login.php`, `authenticate.php`
2. Open a web browser and navigate to localhost. Access the web application first access `setup.php`. This will automatically generate 1000 user accounts with sequential usernames (1, 2, 3, etc.) and passwords each
3. In localhost, navigate to phpMyAdmin. Refresh the page if needed to ensure that the database `brute_auth_pages` with the table `Users` are created <br/>
   ![image](https://github.com/user-attachments/assets/291adb04-d8b8-4aed-a8ef-8cde94357808)
   <br/>
   Mix up some of the passwords to add realism <br/>
   ![image](https://github.com/user-attachments/assets/a83a7d4a-c042-4e83-82f5-e95a0d54459c)

4. Create a python file named `bruteforce.py` to brute force the logins
5. To confirm a random CSRF token is generated and submitted with each login request, inspect the login html page and look for the hidden CSRF token value. Refreshing the page should change the value as shown in the following images <br/>
   ![image](https://github.com/user-attachments/assets/9c4de8f4-b674-429a-9df9-dd1e7264b16c)
6. Store the web page cookie name and value in `browser_cookie.txt` file. The information can be retrieved in the Storage tab <br/>
   ![image](https://github.com/user-attachments/assets/40abfaff-4c95-44ae-88ac-f034d5330c96)
7. Launch the Python script and select Vertical attack <br/>
   ![image](https://github.com/user-attachments/assets/1e236e68-c118-4678-9396-061d9501bbd9)
8. Then try Horizontal attack <br/>
   ![image](https://github.com/user-attachments/assets/9bce44ad-ad00-49b8-b7fd-59141a992ca3)




   

