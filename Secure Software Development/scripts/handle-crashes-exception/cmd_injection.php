<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user_command = $_POST['command'];

    // Vulnerable command execution (no input sanitization)
    $output = shell_exec($user_command);
    echo "<pre>$output</pre>";
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Web App - Command Injection</title>
</head>
<body>
    <h1>Command Injection Vulnerability</h1>
    <form method="post" action="command_injection.php">
        <label for="command">Command:</label>
        <input type="text" id="command" name="command">
        <input type="submit" value="Execute">
    </form>
  <script>
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
