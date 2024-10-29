<?php
include 'config.php';
include 'functions.php';

// Check if form was submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $errors = [];

    // Validate username
    if (!isUsernameValid($username)) {
        $errors[] = "Username must contain only alphanumeric characters.";
    }

    // Check if password is blacklisted
    if (isPasswordBlacklisted($password)) {
        $errors[] = "Password is too common. Please choose a stronger password.";
    } else {
        // If not blacklisted, check if it meets password requirements
        if (!isPasswordValid($password)) {
            $errors[] = "Password must be at least 12 characters long, with uppercase, lowercase, numbers, and special characters.";
        }
    }

    // If there are any validation errors, display them and stop the process
    if (!empty($errors)) {
        foreach ($errors as $error) {
            echo $error . "<br>";
        }
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
