<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Update Password</title>
  <script src="passwordStrength.js" defer></script>
</head>
<body>
  <h2>Update Password</h2>
  <form action="update_password_action.php" method="POST">
    <label for="old_password">Old Password:</label>
    <input type="password" name="old_password" required><br>

    <label for="new_password">New Password:</label>
    <input type="password" id="new_password" name="new_password" required>
    <meter id="password-strength-meter" max="4"></meter>
    <p id="password-strength-text"></p><br>

    <input type="submit" value="Update Password">
  </form>
</body>
</html>
