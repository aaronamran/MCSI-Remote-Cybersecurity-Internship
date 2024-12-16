<?php
session_start();
$servername = "localhost";
$username = "root"; // XAMPP default
$password = ""; // XAMPP default
$dbname = "bruteauth";

$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $input_username = $_POST['username'];
    $input_password = md5($_POST['password']); // Simple MD5 hash for comparison

    // Check for blocked accounts or too many failed attempts
    $sql = "SELECT * FROM users WHERE username = '$input_username'";
    $result = $conn->query($sql);
    $user = $result->fetch_assoc();

    if ($user) {
        $failed_attempts = $user['failed_attempts'];
        $last_failed_attempt = strtotime($user['last_failed_attempt']);

        // If the account is locked due to failed attempts or other criteria
        if ($failed_attempts >= 3 && (time() - $last_failed_attempt) < 60) {
            echo "Account is temporarily locked. Please try again later.";
            exit;
        }

        if ($user['password'] == $input_password) {
            $_SESSION['username'] = $input_username;

            // Reset failed attempts on successful login
            $conn->query("UPDATE users SET failed_attempts = 0 WHERE username = '$input_username'");

            header('Location: dashboard.php');
            exit;
        } else {
            // Increment failed attempts if the password is incorrect
            $failed_attempts++;
            $conn->query("UPDATE users SET failed_attempts = $failed_attempts, last_failed_attempt = NOW() WHERE username = '$input_username'");

            echo "Invalid credentials.";
        }
    } else {
        echo "Username not found.";
    }
}

$conn->close();
?>
