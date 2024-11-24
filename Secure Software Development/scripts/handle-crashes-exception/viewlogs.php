<?php
// Path to the log file
$logFile = __DIR__ . '/logs/errors.log';

// Check if the log file exists
if (!file_exists($logFile)) {
    echo "<p>Log file does not exist.</p>";
    exit;
}

// Read the log file contents
$logContents = file_get_contents($logFile);

// Sanitize the output to prevent HTML or script injection
$safeLogContents = htmlspecialchars($logContents);

// Display the logs
echo "<h1>Application Error Logs</h1>";
echo "<pre>$safeLogContents</pre>";

// Provide a clear button to clear the logs if necessary
echo "<form method='POST' action=''>
        <button type='submit' name='clear_logs'>Clear Logs</button>
      </form>";

// Clear logs if the button is clicked
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['clear_logs'])) {
    file_put_contents($logFile, ""); // Clear the log file
    echo "<p>Logs have been cleared.</p>";
}
?>
