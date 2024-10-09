<?php
session_start();

// Dummy credentials for simplicity
$validUsername = 'admin';
$validPassword = 'password';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Check credentials
    if ($username === $validUsername && $password === $validPassword) {
        // Generate session ID and set HttpOnly cookie
        session_regenerate_id();  // Avoid session fixation
        $_SESSION['loggedin'] = true;

        // Set session cookie with HttpOnly flag
        setcookie(session_name(), session_id(), [
            'httponly' => true,  // Ensure cookie is not accessible via JavaScript
            'secure' => false,   // Set to true if using HTTPS
            'samesite' => 'Strict'
        ]);

        header("Location: dashboard.php");
        exit;
    } else {
        // Redirect back to login on failure
        header("Location: index.php");
        exit;
    }
}
