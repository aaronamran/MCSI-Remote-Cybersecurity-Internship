<?php
session_start();

// Check if the user is logged in
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header("Location: index.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard</title>
</head>
<body>
    <h2>Welcome to your Dashboard!</h2>
    <p>You are logged in as <?php echo htmlentities($validUsername); ?></p>
    <a href="logout.php">Logout</a>
</body>
</html>
