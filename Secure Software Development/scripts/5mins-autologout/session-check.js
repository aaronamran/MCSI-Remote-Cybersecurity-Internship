(function() {
    let timeoutDuration = 300000; // 5 minutes in milliseconds
    let logoutTimer;

    function resetTimer() {
        clearTimeout(logoutTimer);
        logoutTimer = setTimeout(logoutUser, timeoutDuration);
    }

    function logoutUser() {
        window.location.href = "logout.php";
    }

    // Reset the timer on any user activity
    window.onload = resetTimer;
    document.onmousemove = resetTimer;
    document.onkeypress = resetTimer;
})();
