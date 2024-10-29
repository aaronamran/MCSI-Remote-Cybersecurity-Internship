<?php
session_start();
include 'config.php';
include 'functions.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Check if account is locked
    if (isAccountLocked($username)) {
        echo "Account is temporarily locked. Please try again later.";
    } else {
        // Retrieve user details
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        // If the username exists in the database
        if ($user) {
            if ($password === $user['password']) {
                // Reset failed attempts on successful login
                resetFailedAttempts($username);

                // Set session and redirect to secure area
                $_SESSION['username'] = $username;

                // Set secure cookie with Secure and HttpOnly flags
                setcookie(session_name(), session_id(), [
                    'expires' => time() + 3600, // 1-hour expiration
                    'path' => '/',
                    'domain' => '', // Use domain if hosted publicly
                    'secure' => true, // Ensure cookie is sent over HTTPS only
                    'httponly' => true, // Prevent JavaScript access to the cookie
                    'samesite' => 'Strict' // Optional: Prevent cross-site requests
                ]);

                header("Location: secure_area.php");
                exit();
            } else {
                // Increment failed attempts only if password is incorrect
                incrementFailedAttempts($username);

                // Lock account if failed attempts reach 5
                if ($user['failed_attempts'] >= 4) {
                    lockAccount($username);
                    echo "Account locked due to too many failed attempts. Please wait 15 seconds before trying again.";
                } else {
                    $attemptsRemaining = 4 - $user['failed_attempts'];
                    echo "Invalid password. Attempts remaining: " . $attemptsRemaining;
                }
            }
        } else {
            // Username does not exist
            echo "Invalid username.";
        }

        // Button to navigate back to login page
        echo "<br><button onclick=\"window.location.href='login.php'\">Go back to Login</button>";
    }
}
?>
