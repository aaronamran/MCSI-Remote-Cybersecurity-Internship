<?php
// Start a secure session
session_start();

// Simple hardcoded user credentials for demonstration purposes
$valid_username = 'admin';
$valid_password = 'password123';

// Check if form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Basic authentication check
    if ($username === $valid_username && $password === $valid_password) {
        // Generate a session token (session ID) and start session
        $_SESSION['user'] = $username;

        // Set secure cookie with Secure and HttpOnly flags
        setcookie(session_name(), session_id(), [
            'expires' => time() + 3600, // 1-hour expiration
            'path' => '/',
            'domain' => '', // Use domain if hosted publicly
            'secure' => true, // Ensure cookie is sent over HTTPS only
            'httponly' => true, // Prevent JavaScript access to the cookie
            'samesite' => 'Strict' // Optional: Prevent cross-site requests
        ]);

        // Redirect to a protected page after successful login
        header("Location: dashboard.php");
        exit;
    } else {
        echo "Invalid username or password!";
    }
}
?>
