<?php
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // Enforce password policy
    if (strlen($password) < 10) {
        echo "Password must be at least 10 characters long.";
        exit;
    }

    // Hash password
    $passwordHash = password_hash($password, PASSWORD_BCRYPT);

    // Here, insert the user data into the database (omitted for simplicity)
    echo "Registration successful.";
}
?>
