<?php
include 'config.php';
include 'functions.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $errors = [];

    // Validate username format
    if (!isUsernameValid($username)) {
        $errors[] = "Username must contain only alphanumeric characters.";
    } else {
        // Check if username already exists in the database
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $userExists = $stmt->fetchColumn();

        if ($userExists) {
            $errors[] = "Username already exists. Please choose a different one.";
        }
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
        echo "<br><button onclick=\"window.location.href='register_form.php'\">Back to Registration</button>";
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
        echo "Error: " . $e->getMessage();
    }
} else {
    echo "Invalid request.";
}
?>
