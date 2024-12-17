<?php
session_start();

if (isset($_SESSION['username'])) {
    header('Location: dashboard.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    if (authenticate($username, $password)) {
        // Successful login
        $_SESSION['username'] = $username;
        header('Location: dashboard.php');
        exit;
    }
}

function authenticate($username, $password) {
    // Database configuration
    $servername = "localhost";
    $db_username = "root";
    $db_password = "";
    $dbname = "block_brute_force";

    // Create connection
    $conn = new mysqli($servername, $db_username, $db_password, $dbname);

    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // Query to get user data
    $stmt = $conn->prepare("SELECT id, username, password, failed_attempts, last_failed_attempt FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();

    if ($user) {
        $max_attempts = 3;  // Set max attempts to 3
        $lockout_time = 120; // Lockout duration in seconds
        $current_time = time();
        $last_failed_time = strtotime($user['last_failed_attempt']);

        // Check if the user is locked out
        if ($user['failed_attempts'] >= $max_attempts && ($current_time - $last_failed_time) < $lockout_time) {
            // Block login and send a 403 status code
            http_response_code(403);
            echo "<p>Your account is locked due to multiple failed login attempts. Please try again after 2 minutes.</p>";
            $conn->close();
            return false;
        }

        // Password check
        if ($password === $user['password']) {
            // Successful login: Reset failed attempts
            $stmt = $conn->prepare("UPDATE users SET failed_attempts = 0, last_failed_attempt = NULL WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $conn->close();
            return true;
        } else {
            // Increment failed attempts and check if lockout should trigger
            $failed_attempts = $user['failed_attempts'] + 1;

            // Print debugging information
            echo "<p>Failed attempts: " . $failed_attempts . "</p>";

            // If attempts exceed threshold, lock the account and trigger a 403 response
            if ($failed_attempts >= $max_attempts) {
                // Lock account after 3 failed attempts
                http_response_code(403);
                echo "<p>Your account has been locked due to multiple failed login attempts. Please try again after 2 minutes.</p>";
            } else {
                $remaining_attempts = $max_attempts - $failed_attempts;
                echo "<p>Invalid credentials. You have $remaining_attempts attempts remaining.</p>";
            }

            // Update failed attempts in the database
            $stmt = $conn->prepare("UPDATE users SET failed_attempts = ?, last_failed_attempt = NOW() WHERE username = ?");
            $stmt->bind_param("is", $failed_attempts, $username);
            $stmt->execute();

            $conn->close();
            return false;
        }
    } else {
        // Invalid username
        echo "<p>Invalid username or password.</p>";
        $conn->close();
        return false;
    }
}



?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>
    <form action="login.php" method="POST">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>
