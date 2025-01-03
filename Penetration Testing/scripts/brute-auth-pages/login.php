<?php
session_start();

// Check if the CSRF token is already set; if not, create one
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>

<form method="POST" action="authenticate.php">
    Username: <input type="text" name="username" required>
    Password: <input type="password" name="password" required>
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    <button type="submit">Login</button>
</form>
