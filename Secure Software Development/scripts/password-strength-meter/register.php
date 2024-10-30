<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Register</title>
    <link rel="stylesheet" href="style.css">
    <script src="password_strength.js" defer></script>
</head>
<body>
    <h2>Register</h2>
    <form action="process_registration.php" method="POST">
        <label for="username">Username:</label>
        <input type="text" name="username" required><br><br>
        
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required minlength="10">
        <div id="strength-meter" class="strength-meter"></div>
        <div id="crack-time"></div>
        
        <br>
        <button type="submit">Register</button>
    </form>
</body>
</html>
