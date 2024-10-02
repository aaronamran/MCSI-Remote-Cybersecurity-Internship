<?php
// auth_actions.php
include 'db_connect.php';

if (isset($_POST['register'])) {
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT); // Hash password

    // Insert into database
    $sql = "INSERT INTO users (username, password) VALUES ('$username', '$password')";
    if ($conn->query($sql)) {
        echo "Registration successful";
    } else {
        echo "Error: " . $conn->error;
    }
}

if (isset($_POST['login'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Check database for user
    $sql = "SELECT * FROM users WHERE username = '$username'";
    $result = $conn->query($sql);
    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        if (password_verify($password, $user['password'])) {
            echo "Login successful";
        } else {
            echo "Invalid password";
        }
    } else {
        echo "User not found";
    }
}

if (isset($_POST['update_password'])) {
    $new_password = password_hash($_POST['new-password'], PASSWORD_BCRYPT);
    $username = $_SESSION['username']; // Assuming user is logged in

    // Update password in database
    $sql = "UPDATE users SET password = '$new_password' WHERE username = '$username'";
    if ($conn->query($sql)) {
        echo "Password updated successfully";
    } else {
        echo "Error: " . $conn->error;
    }
}
?>
