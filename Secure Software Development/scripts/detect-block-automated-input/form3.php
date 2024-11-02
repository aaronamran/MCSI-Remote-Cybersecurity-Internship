<?php session_start(); ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Form 3</title>
    <link rel="stylesheet" href="style.css">
    <script src="captcha.js"></script>
</head>
<body>
    <h2>Form 3</h2>
    <form action="validate_form.php" method="post" onsubmit="return validateCaptcha()">
        <input type="text" name="input_field" placeholder="Enter text here" required>
        
        <!-- CAPTCHA -->
        <img src="captcha/simple_captcha.php" alt="CAPTCHA">
        <input type="text" name="captcha_input" placeholder="Enter CAPTCHA here" required>
        
        <input type="hidden" name="form_id" value="form3">
        <button type="submit">Submit</button>
    </form>
</body>
</html>
