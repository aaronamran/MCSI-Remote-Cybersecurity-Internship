<?php
// index.php

session_start(); // Start the session to handle login status

include 'db_connect.php'; // Include database connection

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['register'])) {
        // Handle registration
        $username = $_POST['username'];
        $password = $_POST['password'];

        if (strlen($password) < 10) {
            $error = "Password must be at least 10 characters long.";
        } else {
            $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

            $sql = "INSERT INTO users (username, password) VALUES ('$username', '$hashedPassword')";
            if ($conn->query($sql)) {
                $success = "Registration successful!";
            } else {
                $error = "Error: " . $conn->error;
            }
        }
    } elseif (isset($_POST['login'])) {
        // Handle login
        $username = $_POST['username'];
        $password = $_POST['password'];

        $sql = "SELECT * FROM users WHERE username = '$username'";
        $result = $conn->query($sql);
        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
            if (password_verify($password, $user['password'])) {
                $_SESSION['username'] = $username;
                $success = "Login successful!";
            } else {
                $error = "Invalid password.";
            }
        } else {
            $error = "User not found.";
        }
    } elseif (isset($_POST['update_password'])) {
        // Handle password update
        if (isset($_SESSION['username'])) {
            $username = $_SESSION['username'];
            $newPassword = $_POST['new-password'];

            if (strlen($newPassword) < 10) {
                $error = "Password must be at least 10 characters long.";
            } else {
                $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);
                $sql = "UPDATE users SET password = '$hashedPassword' WHERE username = '$username'";
                if ($conn->query($sql)) {
                    $success = "Password updated successfully!";
                } else {
                    $error = "Error: " . $conn->error;
                }
            }
        } else {
            $error = "You must be logged in to update your password.";
        }
    }
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Authentication</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/zxcvbn/4.4.2/zxcvbn.js"></script>
    <script src="passwordStrength.js" defer></script>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <h1>User Authentication System</h1>

    <?php if (isset($error)): ?>
        <div style="color: red;">
            <strong>Error:</strong> <?= htmlspecialchars($error) ?>
        </div>
    <?php endif; ?>

    <?php if (isset($success)): ?>
        <div style="color: green;">
            <strong>Success:</strong> <?= htmlspecialchars($success) ?>
        </div>
    <?php endif; ?>

    <!-- Registration Form -->
    <h2>Register</h2>
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" id="password" name="password" placeholder="Password" required>
        <div id="password-strength"></div>
        <input type="submit" name="register" value="Register">
    </form>

    <!-- Login Form -->
    <h2>Login</h2>
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <input type="submit" name="login" value="Login">
    </form>

    <!-- Password Update Form (only if logged in) -->
    <?php if (isset($_SESSION['username'])): ?>
        <h2>Update Password</h2>
        <form method="POST">
            <input type="password" id="new-password" name="new-password" placeholder="New Password" required>
            <div id="password-strength-update"></div>
            <input type="submit" name="update_password" value="Update Password">
        </form>
    <?php endif; ?>
</body>
</html>
