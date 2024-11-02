function validateCaptcha() {
    const captchaInput = document.querySelector('input[name="captcha_input"]').value;
    if (captchaInput.trim() === '') {
        alert('Please enter the CAPTCHA.');
        return false;
    }
    return true;
}
