<?php
include 'config.php'; // Database connection

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user_input = $_POST['username'];

    // Vulnerable SQL Query (no input validation)
    $sql = "SELECT * FROM users WHERE username = '$user_input'";
    $result = mysqli_query($conn, $sql);

    if ($result && mysqli_num_rows($result) > 0) {
        echo "User found!";
    } else {
        echo "No user found!";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Web App - SQL Injection</title>
</head>
<body>
    <h1>SQL Injection Vulnerability</h1>
    <form method="post" action="vulnerable.php">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username">
        <input type="submit" value="Search">
    </form>
</body>
</html>
