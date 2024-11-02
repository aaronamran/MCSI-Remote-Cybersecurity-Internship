<?php
// index.php
session_start();

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // For demo purposes, "log in" any user
    $_SESSION['user'] = 'user1';
    header('Location: password_update.php');
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>
    <form method="POST" action="">
        <button type="submit">Login as user1</button>
    </form>
</body>
</html>
