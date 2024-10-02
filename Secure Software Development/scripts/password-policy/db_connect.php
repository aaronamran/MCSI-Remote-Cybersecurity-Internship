<?php
$servername = "localhost";
$username = "root"; // Set your MySQL username
$password = ""; // Set your MySQL password
$dbname = "user_auth";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
