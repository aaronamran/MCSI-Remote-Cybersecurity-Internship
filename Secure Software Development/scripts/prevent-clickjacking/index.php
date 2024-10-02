 <?php
 // Setting the X-Frame-Options header
 header('X-Frame-Options: DENY');
 ?>
 <!DOCTYPE html>
 <html lang="en">
 <head>
     <meta charset="UTF-8">
     <meta name="viewport" content="width=device-width, initial-scale=1.0">
     <title>Clickjacking Prevention App</title>
     <style>
         body {
             font-family: Arial, sans-serif;
             text-align: center;
             padding: 50px;
         }
     </style>
     <script>
         // Detect if the page is loaded in an iframe
         if (window.top !== window.self) {
             alert('This application cannot be loaded in an iframe.');
             window.top.location = window.self.location; // Redirect to break out of iframe
         }
     </script>
 </head>
 <body>
     <h1>Welcome to the Secure Web Application!</h1>
     <p>This application is protected against clickjacking.</p>
 </body>
 </html>
