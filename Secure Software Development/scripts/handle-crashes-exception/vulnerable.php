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
    <script>
        // JS error handling
        window.onerror = function(message, source, lineno, colno, error) {
        // Send error details to server-side logging script (log_error.php)
        fetch('log_error.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: message,
                source: source,
                lineno: lineno,
                colno: colno,
                error: error
            })
        });
    
        // Display a generic message to the user
        alert("An error occurred, but don't worry! We're working on it.");
        
        // Prevent the error from appearing in the browser console
        return true;
        };
    </script>

</body>
</html>
