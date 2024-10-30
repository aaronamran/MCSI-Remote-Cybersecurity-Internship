document.addEventListener('DOMContentLoaded', () => {
    const passwordInput = document.getElementById('password');
    const strengthMeter = document.getElementById('strength-meter');
    const crackTimeDisplay = document.getElementById('crack-time');

    passwordInput.addEventListener('input', updateStrengthMeter);

    function updateStrengthMeter() {
        const password = passwordInput.value;
        const strength = getPasswordStrength(password);
        strengthMeter.textContent = `Strength: ${strength}`;

        if (strength === 'Weak') {
            strengthMeter.style.color = 'red';
        } else if (strength === 'Moderate') {
            strengthMeter.style.color = 'orange';
        } else if (strength === 'Strong') {
            strengthMeter.style.color = 'green';
        }
        
        const crackTime = estimateCrackTime(password);
        crackTimeDisplay.textContent = `Estimated Crack Time: ${crackTime}`;
    }

    function getPasswordStrength(password) {
        const length = password.length;
        let strength = 'Weak';
        
        if (length >= 10 && /[A-Z]/.test(password) && /[0-9]/.test(password) && /[\W_]/.test(password)) {
            strength = 'Strong';
        } else if (length >= 10 && (/[A-Z]/.test(password) || /[0-9]/.test(password) || /[\W_]/.test(password))) {
            strength = 'Moderate';
        }

        return strength;
    }

    function estimateCrackTime(password) {
        // Basic entropy calculation based on character set size
        let entropy = 0;
        if (/[a-z]/.test(password)) entropy += 26;
        if (/[A-Z]/.test(password)) entropy += 26;
        if (/[0-9]/.test(password)) entropy += 10;
        if (/[\W_]/.test(password)) entropy += 32;
        
        const combinations = Math.pow(entropy, password.length);
        const guessesPerSecond = 1e9; // Assume 1 billion guesses per second
        const crackTimeSeconds = combinations / guessesPerSecond;
        
        return formatTime(crackTimeSeconds);
    }

    function formatTime(seconds) {
        if (seconds < 60) return `${seconds.toFixed(2)} seconds`;
        const minutes = seconds / 60;
        if (minutes < 60) return `${minutes.toFixed(2)} minutes`;
        const hours = minutes / 60;
        if (hours < 24) return `${hours.toFixed(2)} hours`;
        const days = hours / 24;
        if (days < 365) return `${days.toFixed(2)} days`;
        const years = days / 365;
        return `${years.toFixed(2)} years`;
    }
});
