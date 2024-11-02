<?php
session_start();

header('Content-type: image/png');
$image = imagecreate(120, 40);
$background = imagecolorallocate($image, 255, 255, 255);
$textColor = imagecolorallocate($image, 0, 0, 0);

$captcha_code = '';
for ($i = 0; $i < 5; $i++) {
    $captcha_code .= chr(rand(65, 90));
}
$_SESSION['captcha_code'] = $captcha_code;

imagestring($image, 5, 10, 10, $captcha_code, $textColor);
imagepng($image);
imagedestroy($image);
?>
