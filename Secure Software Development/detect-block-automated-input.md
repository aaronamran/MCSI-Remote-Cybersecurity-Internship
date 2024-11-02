# Write A Web Application That Detects And Blocks Automated Input Submission Tools
Web applications often face attacks from automated web crawlers and bots, which can spam forms with malicious or obnoxious data. To protect against such attacks, developers need to implement security measures that detect and block automated input submission tools


## References
- [OWASP Periodic Table of Vulnerabilities - Brute Force (Generic) / Insufficient Anti-automation](https://wiki.owasp.org/index.php/OWASP_Periodic_Table_of_Vulnerabilities_-_Brute_Force_(Generic)_/_Insufficient_Anti-automation) by OWASP
- [Burp Suite Professional / Community 1.7.36](https://portswigger.net/burp/releases/professional-community-1-7-36) by PortSwigger
- [Installing W4AF using Docker](https://w4af.readthedocs.io/en/latest/install.html#installing-using-docker) by w4af


## Tasks
- Create a web application with the following features:
  - Include five different forms that unauthenticated users can access and submit
  - Utilize JavaScript to add a challenge-response mechanism to each form. (You can implement CAPTCHA or reCAPTCHA challenges to distinguish human users from automated bots)




## Benchmarks
- Host the web application on a web server and make sure the challenge-response mechanisms and CAPTCHA/reCAPTCHA challenges are in place
- Configure and run OWASP ZAP to perform automated input submission attacks against the web application
- The web application successfully detects and blocks attacks from OWASP ZAP
- Configure and run Burp Suite Spider to perform automated input submission attacks against the web application
- The web application successfully detects and blocks attacks from Burp Suite Spider



## Solutions With Scripts
- [Link to the folder of scripts](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/tree/main/Secure%20Software%20Development/scripts/detect-block-automated-input)
<br/>
1. 
