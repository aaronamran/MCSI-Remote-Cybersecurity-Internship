<?php
include 'config.php';

function hashPassword($password) {
    return hash('sha256', $password);
}

function isUsernameValid($username) {
    return preg_match('/^[a-zA-Z0-9]+$/', $username);
}

function isPasswordValid($password) {
    $minLength = 12;
    return strlen($password) >= $minLength &&
           preg_match('/[A-Z]/', $password) &&
           preg_match('/[a-z]/', $password) &&
           preg_match('/[0-9]/', $password) &&
           preg_match('/[!@#$%^&*(),.?":{}|<>]/', $password);
}

function isPasswordBlacklisted($password) {
    $blacklistedPasswords = [
        "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567", 
        "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein", "696969", "shadow", 
        "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890", "michael", "654321", "pussy", 
        "superman", "1qaz2wsx", "7777777", "fuckyou", "121212", "000000", "qazwsx", "123qwe", "killer", 
        "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer", "harley", 
        "batman", "andrew", "tigger", "sunshine", "iloveyou", "fuckme", "2000", "charlie", "robert", 
        "thomas", "hockey", "ranger", "daniel", "starwars", "klaster", "112233", "george", "asshole", 
        "computer", "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111", "131313", 
        "freedom", "777777", "pass", "fuck", "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua", 
        "cheese", "amanda", "summer", "love", "ashley", "6969", "nicole", "chelsea", "biteme", "matthew", 
        "access", "yankees", "987654321", "dallas", "austin", "thunder", "taylor", "matrix"
    ];
    return in_array($password, $blacklistedPasswords);
}

function lockAccount($username) {
    global $pdo;
    $stmt = $pdo->prepare("UPDATE users SET lock_time = NOW(), failed_attempts = 0 WHERE username = ?");
    $stmt->execute([$username]);
}

function isAccountLocked($username) {
    global $pdo;
    $stmt = $pdo->prepare("SELECT lock_time FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user && $user['lock_time'] !== null) {
        $lockDuration = 15; // Lockout duration in seconds (15 seconds)
        $lockEndTime = strtotime($user['lock_time']) + $lockDuration;
        if (time() < $lockEndTime) {
            return true; // Account is still locked
        } else {
            resetFailedAttempts($username); // Reset lock if duration has passed
            return false;
        }
    }
    return false;
}

function incrementFailedAttempts($username) {
    global $pdo;
    $stmt = $pdo->prepare("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?");
    $stmt->execute([$username]);
}

function resetFailedAttempts($username) {
    global $pdo;
    $stmt = $pdo->prepare("UPDATE users SET failed_attempts = 0, lock_time = NULL WHERE username = ?");
    $stmt->execute([$username]);
}
?>
