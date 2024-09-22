# Write A PHP Application With An Exposed phpinfo.php Page
An exposed `phpinfo.php` page poses a security risk by revealing sensitive server details, including PHP versions, modules, and configurations. Attackers can exploit this information to identify vulnerabilities, making it essential for developers and administrators to secure or remove such pages.

## References
- [Is it Secret? Is it Safe?](https://perishablepress.com/htaccess-secure-phpinfo-php/) by Perishable Press
- [Show PHP Settings with phpinfo and Example PHP $_SERVER Display Page](https://tekeye.uk/vps/show-php-settings) by Daniel S. Fowler, Tek Eye

## Tasks
- [Install a local web server like XAMPP](https://hackernoon.com/how-to-install-xampp-on-linux-a-quick-step-by-step-guide) for testing 
- Create a basic PHP web application with a homepage
- Add a new PHP file named phpinfo.php to the web application root directory
- Inside the phpinfo.php file, add a function to display PHP version information
- Host the vulnerable web application
- Access the web application default homepage
- Access the vulnerable PHP info page


## Benchmarks
- Confirm that the PHP information is displayed in the browser
- Show detailed information about the PHP installation and server configuration


## Steps with Solutions
1. Navigate to the web application directory <br/>
   If using XAMPP, the files are placed in the `htdocs` folder. The default location for this folder is:
      - Windows: `C:\xampp\htdocs\`
      - Linux/macOS: `/opt/lampp/htdocs/` 
      - For organised folders, a subdirectory in `htdocs` folder can be made
2. Create `index.php` as a simple homepage:
   ```
   <?php
   // index.php
   echo "<h1>Welcome to the Simple PHP Web Application</h1>";
   echo "<p>This is the homepage of the web application.</p>";
   echo "<p>Enter phpinfo.php at the end of the URL to access the PHP info page.</p>";
   ?>
   ```
3. Add a vulnerable `phpinfo.php` page:
   ```
   <?php
   // phpinfo.php
   // Exposing the PHP version, modules, environment variables and server configuration
   phpinfo();
   ?>
   ```
4. Host the Vulnerable Web Application:
   - Start Apache from the XAMPP control panel (or manually, if using LAMP).
   - Place the files (index.php and phpinfo.php) in the htdocs folder.
5. Access the Web Application: <br/>
   Open your browser and go to the following URL to access the homepage:
   `http://localhost/index.php` <br/>
   or if it is saved in a subdirectory called phpinfoapp:
   `http://localhost/phpinfoapp/`
7. Access the Vulnerable phpinfo.php Page: <br/>
   Visit the following URL to access the exposed phpinfo.php page:
   `http://localhost/phpinfo.php` or `http://localhost/phpinfoapp/phpinfo.php`
8. (Optional) Secure the page: <br/>
   You can secure the phpinfo.php page by restricting access or deleting it altogether in a live environment.
   ```
   <?php
   // A simple way to restrict access to phpinfo.php
   if ($_SERVER['REMOTE_ADDR'] !== '127.0.0.1') {
      die("Access denied");
   }
   phpinfo();
   ?>
   ```

