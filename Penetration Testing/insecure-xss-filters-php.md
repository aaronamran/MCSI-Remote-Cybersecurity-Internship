# Write A Web Application With Insecure XSS Filters
An insecure XSS filter occurs when an application fails to properly validate user input, allowing attackers to inject malicious code into web pages. Some developers use blacklists to block dangerous strings like `<script` or `onload=` but often miss edge cases, leaving the application vulnerable to XSS attacks.

## References
- [OWASP - XSS Filter Evasion Cheat Sheet](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet) by OWASP

## Tasks
- Write a simple web application containing multiple input fields that are vulnerable to cross-site scripting
- Apply insecure filtering mechanisms to these input fields, such as a blacklist that attempts to block commonly known dangerous XSS keywords
- Develop a blacklist containing at least 30 dangerous XSS keywords (e.g., `<script>`, `onload=`, `alert(`, etc.) that you plan to use to try and protect the input fields
- Use various XSS techniques, such as HTML encoding, JavaScript obfuscation, and bypassing blacklist filters, to inject malicious JavaScript code into the input fields
- Verify that the injected malicious JavaScript code is executed on the web application's frontend, demonstrating the bypass of the insecure XSS filters

## Steps With Solutions
1. Create a new PHP file named `vulnerable_xss.php` in the htdocs folder in XAMPP 
2. PHP for vulnerable web application:
   ```
   <?php
   // XSS Blacklist - 30 dangerous XSS keywords
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
       foreach ($blacklist as $word) {
           if (stripos($input, $word) !== false) {
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
           // Display the user's input directly (vulnerable to XSS)
           echo "User Input: " . htmlspecialchars($user_input);
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
       <form action="vulnerable_xss.php" method="POST">
           <label for="user_input">Enter some text:</label><br>
           <input type="text" id="user_input" name="user_input"><br><br>
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
4. To test the vulnerability, perform the following
   - Inject JavaScript into the form input, such as the line of code below. It will trigger an alert if the blacklist is bypassed
     ```
     <img src="x" onerror="alert('XSS')">
     ```
   - Test different bypass techniques like encoding, whitespace, or breaking keywords
     ```
     <scr<script>ipt>alert('XSS')</script>
     ```
   - Try using encoded input like
     ```
     &#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;
     ```
5. For validation purposes, ensure that the injected JavaScript successfully executes on the frontend (e.g., showing an alert box) and different bypass techniques successfully trigger the XSS, demonstrating the insecure filter
