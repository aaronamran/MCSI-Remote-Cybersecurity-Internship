<?php
session_start();
$db = new PDO('mysql:host=localhost;dbname=webapp', 'root', '');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("CSRF token validation failed.");
    }

    // Validate credentials
    $username = $_POST['username'];
    $password = $_POST['password'];
    $stmt = $db->prepare("SELECT password FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password'])) {
        echo "Login successful!";
    } else {
        echo "Invalid credentials.";
    }
}
?>
