<?php
session_start();

// Check if the user is logged in
if (!isset($_SESSION['username'])) {
    // Redirect to login page if not logged in
    header("Location: login.php");
    exit();
}

// Display a success message
echo "<h1>Welcome, " . htmlspecialchars($_SESSION['username']) . "!</h1>";
echo "<p>You have successfully logged in.</p>";
echo '<a href="logout.php">Logout</a>'; // Logout link
?>
