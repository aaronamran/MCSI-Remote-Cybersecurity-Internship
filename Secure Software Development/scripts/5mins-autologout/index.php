<?php
session_start();

// Check if the user is already logged in
if (isset($_SESSION['username'])) {
    header('Location: dashboard.php');
    exit();
}

// Dummy credentials for the purpose of this example
$valid_username = 'user';
$valid_password = 'password';

// Handle form submission for login
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Check if the submitted credentials are valid
    if ($username === $valid_username && $password === $valid_password) {
        // Set the session variables
        $_SESSION['username'] = $username;
        $_SESSION['last_activity'] = time(); // Set last activity time
        header('Location: dashboard.php');
        exit();
    } else {
        $error_message = "Invalid username or password.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>

    <?php
    // Show error message if credentials are wrong
    if (isset($error_message)) {
        echo "<p style='color:red;'>$error_message</p>";
    }

    // Show message if session timed out
    if (isset($_GET['timeout']) && $_GET['timeout'] == 1) {
        echo "<p style='color:red;'>Session timed out. Please log in again.</p>";
    }
    ?>

    <form method="POST" action="index.php">
        <label for="username">Username:</label>
        <input type="text" name="username" id="username" required><br><br>

        <label for="password">Password:</label>
        <input type="password" name="password" id="password" required><br><br>

        <input type="submit" value="Login">
    </form>
</body>
</html>
