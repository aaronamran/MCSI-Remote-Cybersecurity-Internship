<?php
// Connect to the database (Assuming database and 'users' table already created)
$db = new PDO('mysql:host=localhost;dbname=webapp', 'root', '');

// Generate 1000 users with weak and strong passwords
for ($i = 1; $i <= 1000; $i++) {
    $username = $i;
    $password = $i % 5 === 0 ? 'password' : bin2hex(random_bytes(5)); // Weak password for some users
    $hashed_password = password_hash($password, PASSWORD_BCRYPT);
    $db->query("INSERT INTO users (username, password) VALUES ('$username', '$hashed_password')");
}
echo "User accounts created.";
?>
