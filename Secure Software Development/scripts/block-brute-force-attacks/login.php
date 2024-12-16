<?php
session_start();
$max_attempts = 3; // Max attempts before lockout
$lockout_time = 120; // Lockout duration in seconds (2 minutes)
$login_attempts = isset($_SESSION['login_attempts']) ? $_SESSION['login_attempts'] : 0;
$last_attempt_time = isset($_SESSION['last_attempt_time']) ? $_SESSION['last_attempt_time'] : 0;

if ($login_attempts >= $max_attempts && (time() - $last_attempt_time) < $lockout_time) {
    // Account is locked
    echo "<p>Your account is locked due to multiple failed login attempts. Please try again after 2 minutes.</p>";
    exit;
}

if (isset($_SESSION['username'])) {
    header('Location: dashboard.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Perform authentication (dummy check for example)
    if (authenticate($username, $password)) {
        $_SESSION['username'] = $username;
        $_SESSION['login_attempts'] = 0; // Reset login attempts on successful login
        header('Location: dashboard.php');
        exit;
    } else {
        $_SESSION['login_attempts'] = $login_attempts + 1;
        $_SESSION['last_attempt_time'] = time();
        $remaining_attempts = $max_attempts - $_SESSION['login_attempts'];
        echo "<p>Invalid credentials. You have $remaining_attempts attempts remaining.</p>";
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

    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // Query to get the user's data from the database
    $stmt = $conn->prepare("SELECT id, username, password, failed_attempts, last_failed_attempt FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();

    if ($user) {
        // Check if the user has been locked out due to failed attempts
        $lockout_time = 300; // 5 minutes lockout duration (in seconds)
        $current_time = time();
        
        if ($user['failed_attempts'] >= 5 && (strtotime($user['last_failed_attempt']) + $lockout_time) > $current_time) {
            // If the account is locked out
            echo "Your account is locked due to multiple failed login attempts. Please try again later.";
            return false;
        }

        // Check if the password matches
        if (password_verify($password, $user['password'])) {
            // If the password is correct, reset failed attempts
            $stmt = $conn->prepare("UPDATE users SET failed_attempts = 0, last_failed_attempt = NULL WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();

            $conn->close();
            return true; // Successful login
        } else {
            // Increment failed attempts and update last failed attempt time
            $failed_attempts = $user['failed_attempts'] + 1;
            $stmt = $conn->prepare("UPDATE users SET failed_attempts = ?, last_failed_attempt = NOW() WHERE username = ?");
            $stmt->bind_param("is", $failed_attempts, $username);
            $stmt->execute();

            $conn->close();
            return false; // Incorrect password
        }
    } else {
        // If the user doesn't exist
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
