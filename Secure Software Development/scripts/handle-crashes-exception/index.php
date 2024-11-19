<?php
// Database Configuration
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "vulnerable_app";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// SQL Injection Vulnerability
if (isset($_GET['user_id'])) {
    $user_id = $_GET['user_id']; // User input directly used in query
    $query = "SELECT * FROM users WHERE id = $user_id";
    $result = $conn->query($query);

    if ($result->num_rows > 0) {
        while ($row = $result->fetch_assoc()) {
            echo "Username: " . htmlspecialchars($row['username']) . "<br>";
        }
    } else {
        echo "No results found.";
    }
}

// Command Injection Vulnerability
if (isset($_POST['cmd'])) {
    $cmd = $_POST['cmd']; // User input directly executed
    $output = shell_exec($cmd);
    echo "<pre>" . htmlspecialchars($output) . "</pre>";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vulnerable App</title>
</head>
<body>
    <h1>Vulnerable Web Application</h1>

    <h2>SQL Injection Example</h2>
    <form method="GET">
        <label for="user_id">User ID:</label>
        <input type="text" name="user_id" id="user_id">
        <button type="submit">Search</button>
    </form>

    <h2>Command Injection Example</h2>
    <form method="POST">
        <label for="cmd">Command:</label>
        <input type="text" name="cmd" id="cmd">
        <button type="submit">Run</button>
    </form>
</body>
</html>
