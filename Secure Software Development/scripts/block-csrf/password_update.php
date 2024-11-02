<?php
// password_update.php
session_start();
include 'csrf_token.php';

if (!isset($_SESSION['user'])) {
    header('Location: index.php');
    exit();
}

// Generate CSRF token for this session
$csrf_token = generateToken();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Password Update</title>
</head>
<body>
    <h2>Update Password</h2>
    <form method="POST" action="process_update.php">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
        <label for="new_password">New Password:</label>
        <input type="password" id="new_password" name="new_password" required>
        <button type="submit">Update Password</button>
    </form>
</body>
</html>
