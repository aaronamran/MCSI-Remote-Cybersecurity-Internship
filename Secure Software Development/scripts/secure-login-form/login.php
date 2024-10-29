<?php
include 'functions.php';
session_start();

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $hashedPassword = hashPassword($password);

    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user && $user['lock_time'] && strtotime($user['lock_time']) > strtotime('-15 minutes')) {
        echo "Account is locked. Try again later.";
        exit;
    }

    if ($user && $user['password'] === $hashedPassword) {
        $_SESSION['user'] = $username;

        setcookie("PHPSESSID", session_id(), 0, "/", "", true, true);

        $stmt = $pdo->prepare("UPDATE users SET failed_attempts = 0, lock_time = NULL WHERE username = ?");
        $stmt->execute([$username]);

        echo "Login successful!";
    } else {
        if ($user) {
            incrementFailedAttempts($username);
            if ($user['failed_attempts'] >= 5) {
                lockAccount($username);
                echo "Account locked due to multiple failed attempts.";
                exit;
            }
        }
        echo "Invalid credentials.";
    }
}
?>
