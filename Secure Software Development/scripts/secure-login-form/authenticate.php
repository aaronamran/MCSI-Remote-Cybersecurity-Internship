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

        if ($user && hashPassword($password) === $user['password']) {
            // Reset failed attempts on successful login
            resetFailedAttempts($username);

            // Set session and redirect to secure area
            $_SESSION['username'] = $username;
            header("Location: secure_area.php");
            exit();
        } else {
            // Increment failed attempts on failed login
            incrementFailedAttempts($username);

            // Lock account if failed attempts reach 5
            if ($user && $user['failed_attempts'] >= 4) {
                lockAccount($username);
                echo "Account locked due to too many failed attempts. Please wait 30 seconds before trying again.";
            } else {
                $attemptsRemaining = $user ? (4 - $user['failed_attempts']) : 4;
                echo "Invalid username or password. Attempts remaining: " . $attemptsRemaining;
            }

            // Button to navigate back to login page
            echo "<br><button onclick=\"window.location.href='login.php'\">Go back to Login</button>";
        }
    }
}
?>
