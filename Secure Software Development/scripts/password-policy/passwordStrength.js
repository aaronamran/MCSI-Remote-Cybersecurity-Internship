document.addEventListener('DOMContentLoaded', function () {
    var passwordInput = document.getElementById('password');
    var updatePasswordInput = document.getElementById('new-password');
    var strengthDisplay = document.getElementById('password-strength');
    var updateStrengthDisplay = document.getElementById('password-strength-update');

    function checkPasswordStrength(password, displayElement) {
        var result = zxcvbn(password);
        displayElement.textContent = `Strength: ${result.score} (${result.crack_times_display.offline_slow_hashing_1e4_per_second} to crack)`;
        // Customize the strength display with visual feedback based on `result.score`
    }

    if (passwordInput) {
        passwordInput.addEventListener('input', function () {
            checkPasswordStrength(passwordInput.value, strengthDisplay);
        });
    }

    if (updatePasswordInput) {
        updatePasswordInput.addEventListener('input', function () {
            checkPasswordStrength(updatePasswordInput.value, updateStrengthDisplay);
        });
    }
});
