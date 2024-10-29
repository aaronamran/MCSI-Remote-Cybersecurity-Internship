<?php
include 'functions.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    if (!isUsernameValid($username)) {
        echo "Username must be alphanumeric.";
        exit;
    }

    if (!isPasswordValid($password) || isPasswordBlacklisted($password)) {
        echo "Password does not meet security requirements or is blacklisted.";
        exit;
    }

    $hashedPassword = hashPassword($password);

    // Insert user
    $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->execute([$username, $hashedPassword]);
    echo "Registration successful!";
}
?>
