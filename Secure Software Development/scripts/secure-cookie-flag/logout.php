<?php
session_start();
session_unset();
session_destroy();

// Destroy the secure cookie as well
setcookie(session_name(), '', time() - 3600, '/', '', true, true);

header("Location: login.php");
exit;
?>
