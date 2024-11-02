<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $form_id = $_POST['form_id'];
    $captcha_input = $_POST['captcha_input'];

    if ($captcha_input === $_SESSION['captcha_code']) {
        // CAPTCHA validation succeeded
        echo "Form submission successful for $form_id.";
    } else {
        // CAPTCHA validation failed
        echo "CAPTCHA verification failed. Please try again.";
    }
} else {
    header("Location: index.php");
    exit();
}
?>
