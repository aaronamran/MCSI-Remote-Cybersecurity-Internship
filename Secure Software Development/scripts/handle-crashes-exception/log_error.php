<?php
// log_error.php

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get the JSON payload from the client-side JavaScript
    $data = json_decode(file_get_contents('php://input'), true);

    // Prepare the log message
    $log_message = "[" . date("Y-m-d H:i:s") . "] Error: " . $data['message'] . " in " . $data['source'] . " on line " . $data['lineno'] . "\n";

    // Save the error message securely in a log file (ensure this path is secure)
    file_put_contents('/path/to/secure/logs/error_log.txt', $log_message, FILE_APPEND | LOCK_EX);

    // Respond to the client-side script
    echo json_encode(["message" => "Error logged successfully"]);
}
?>
