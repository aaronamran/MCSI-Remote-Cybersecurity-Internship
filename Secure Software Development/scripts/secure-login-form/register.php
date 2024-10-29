<?php
include 'config.php';
include 'functions.php';

// Check if form was submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Validate username and password
    if (!isUsernameValid($username)) {
        echo "Username must contain only alphanumeric characters.";
        exit;
    }
    if (!isPasswordValid($password)) {
        echo "Password must be at least 12 characters long, with uppercase, lowercase, numbers, and special characters.";
        exit;
    }
    if (isPasswordBlacklisted($password)) {
        echo "Password is too common. Please choose a stronger password.";
        exit;
    }

    // Hash the password
    $hashedPassword = hashPassword($password);

    // Insert user into database
    try {
        $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        $stmt->execute([$username, $hashedPassword]);
        echo "Registration successful. <a href='login.php'>Click here to login</a>";
    } catch (PDOException $e) {
        if ($e->getCode() == 23000) { // Duplicate entry error
            echo "Username already exists. Please choose a different one.";
        } else {
            echo "Error: " . $e->getMessage();
        }
    }
} else {
    echo "Invalid request.";
}
?>
