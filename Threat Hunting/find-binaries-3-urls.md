# Write A YARA Rule That Can Find Binaries That Have More Than 3 URLs
YARA rules are powerful tools for threat hunting, enabling the detection of malware, malicious files, and infections. They allow for quick identification of threats by scanning systems. One use of YARA is searching for embedded URLs, helping to uncover phishing scams or malicious content.

## References
- [Writing YARA Rules](https://yara.readthedocs.io/en/v3.8.1/writingrules.html) by VirusTotal

## Tasks
1. Complete the following prerequisites first:
   - [Lab Setup: Threat Hunting With YARA](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/threat-hunting-yara.md)
   - [Lab Setup: Malware Dataset](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/malware-dataset.md)
   - [Write A YARA Rule That Is Professionally Documented](https://github.com/aaronamran/MCSI-Remote-Cybersecurity-Internship/blob/main/Threat%20Hunting/pro-documented-yara-rule.md)
2. Write a YARA rule that has the following characteristics:
   - Exclude files that are not executables
   - Detect files that contain the keyword "http://" at least 3 times
   - Detect files that contain the keyword "https://" at least 3 times
   - Detect files for which the combined count of keywords "http://" and "https://" is greater than 3
3. Save the YARA rule as "more_than_3_urls.yar" in a location on the hard drive
4. Follow along the "YARA Rules Testing" guideline and test your rule
5. Ensure that the YARA rule accurately identifies files with more than 3 URLs embedded

## Solutions With Scripts
Link to YARA rule
1. YARA rule:
   ```
   rule more_than_3_urls
   {
       meta:
           description = "Detects executable files with more than 3 occurrences of URLs (http:// or https://)"
           author = "Aaron Amran"
           date = "2024-09-26"
   	version = "1.0"

    strings:
        $http = "http://"
        $https = "https://"

    condition:
        // Check if file is a Portable Executable (PE) and count the number of URLs
        uint16(0) == 0x5A4D and 
        ( 
            #http >= 3 or 
            #https >= 3 or 
            (#http + #https) > 3
        )
   }
   ```
2. 

   
   `yara64.exe -r "C:\Users\bboyz\OneDrive\Desktop\MCSI Remote Cybersecurity Internship\Threat Hunting\more_than_3_urls.yar" "C:\Windows\System32"`
   

     
