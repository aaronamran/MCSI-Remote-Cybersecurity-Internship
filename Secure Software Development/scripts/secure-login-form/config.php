<?php
// Database configuration
$host = 'localhost';
$dbname = 'secure_login';
$username = 'root';
$password = '';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

// Secure session settings for cookies
session_set_cookie_params([
    'lifetime' => 0,               // Expires when the browser is closed
    'path' => '/',
    'domain' => 'localhost',       // Change to your domain if not on localhost
    'secure' => true,              // Only send cookie over HTTPS
    'httponly' => true,            // Prevents JavaScript access to session cookie
    'samesite' => 'Strict'         // Protects against CSRF attacks
]);

// Start the session with secure cookie settings
session_start();

// Ensure that any active session gets the secure settings
if (session_status() === PHP_SESSION_ACTIVE) {
    session_regenerate_id(true); // Regenerates the session ID to prevent session fixation
}
?>
