<?php
require 'db_connect.php';
session_start();

if (!isset($_SESSION['user_id'])) {
    echo "You must be logged in to update your password.";
    exit();
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $old_password = $_POST['old_password'];
    $new_password = $_POST['new_password'];
    
    if (strlen($new_password) < 10) {
        echo "Password must be at least 10 characters.";
        exit();
    }

    // Get the current user's password
    $sql = "SELECT password FROM users WHERE id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $_SESSION['user_id']);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();

    // Verify old password
    if (password_verify($old_password, $user['password'])) {
        // Hash and update new password
        $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
        $sql = "UPDATE users SET password = ? WHERE id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("si", $hashed_password, $_SESSION['user_id']);
        if ($stmt->execute()) {
            echo "Password updated successfully!";
        } else {
            echo "Error updating password.";
        }
    } else {
        echo "Old password is incorrect.";
    }
    $stmt->close();
    $conn->close();
}
?>
