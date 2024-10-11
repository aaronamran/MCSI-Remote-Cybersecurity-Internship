session_start();

// Check if the user is logged in
if (!isset($_SESSION['username'])) {
    header('Location: index.php?login_required=1');
    exit();
}

// Set inactivity limit (5 minutes = 300 seconds)
$session_timeout = 300;

// If session has been inactive for more than 5 minutes, log out
if (time() - $_SESSION['last_activity'] > $session_timeout) {
    session_unset();
    session_destroy();
    header('Location: index.php?timeout=1');
    exit();
} else {
    // Reset the last activity time
    $_SESSION['last_activity'] = time();
}

// Calculate remaining time
$remaining_time = $session_timeout - (time() - $_SESSION['last_activity']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <script src="session-check.js"></script>
</head>
<body>
    <h2>Welcome to the Dashboard, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h2>
    <p>This page is protected.</p>

    <!-- Countdown Timer Display -->
    <p>Time remaining before auto logout: <span id="countdown"></span></p>

    <a href="logout.php">Logout</a>

    <script>
        let remainingTime = <?php echo $remaining_time; ?>;

        function startCountdown() {
            let countdownElement = document.getElementById('countdown');

            let countdownInterval = setInterval(function() {
                let minutes = Math.floor(remainingTime / 60);
                let seconds = remainingTime % 60;
                seconds = seconds < 10 ? '0' + seconds : seconds;
                countdownElement.innerHTML = minutes + ":" + seconds;

                if (remainingTime <= 0) {
                    clearInterval(countdownInterval);
                    window.location.href = 'logout.php';
                }

                remainingTime--;
            }, 1000);
        }

        window.onload = startCountdown;
    </script>
</body>
</html>
