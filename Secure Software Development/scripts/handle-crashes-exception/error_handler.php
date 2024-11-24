<?php
// Custom error handler
function customErrorHandler($errno, $errstr, $errfile, $errline) {
    // need to create log directory to prevent logging errors
    $logFile = __DIR__ . '/logs/errors.log';

    // Log error details securely
    $errorDetails = "[" . date('Y-m-d H:i:s') . "] Error: $errstr in $errfile on line $errline\n";
    file_put_contents($logFile, $errorDetails, FILE_APPEND);

    // Show generic error message to the user
    echo "An error occurred. Please try again later.";
}

// Set custom error handler
set_error_handler("customErrorHandler");
?>
