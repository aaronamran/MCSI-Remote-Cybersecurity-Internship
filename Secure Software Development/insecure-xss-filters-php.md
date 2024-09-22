# Write A Web Application With Insecure XSS Filters
An insecure XSS filter occurs when an application fails to properly validate user input, allowing attackers to inject malicious code into web pages. Some developers use blacklists to block dangerous strings like "<script" or "onload=" but often miss edge cases, leaving the application vulnerable to XSS attacks.

## References
- [OWASP - XSS Filter Evasion Cheat Sheet](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet) by OWASP

## Tasks
- Write a simple web application containing multiple input fields that are vulnerable to cross-site scripting
- Apply insecure filtering mechanisms to these input fields, such as a blacklist that attempts to block commonly known dangerous XSS keywords
- Develop a blacklist containing at least 30 dangerous XSS keywords (e.g., "<script>", "onload=", "alert(", etc.) that you plan to use to try and protect the input fields
- Use various XSS techniques, such as HTML encoding, JavaScript obfuscation, and bypassing blacklist filters, to inject malicious JavaScript code into the input fields
- Verify that the injected malicious JavaScript code is executed on the web application's frontend, demonstrating the bypass of the insecure XSS filters

