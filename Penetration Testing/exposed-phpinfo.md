# Write A PHP Application With An Exposed phpinfo.php Page
An exposed `phpinfo.php` page poses a security risk by revealing sensitive server details, including PHP versions, modules, and configurations. Attackers can exploit this information to identify vulnerabilities, making it essential for developers and administrators to secure or remove such pages.

## References
- [Is it Secret? Is it Safe?](https://perishablepress.com/htaccess-secure-phpinfo-php/) by Perishable Press
- [Show PHP Settings with phpinfo and Example PHP $_SERVER Display Page](https://tekeye.uk/vps/show-php-settings) by Daniel S. Fowler, Tek Eye

## Tasks
- Install local web server like XAMPP for testing
- Create a basic PHP web application with a homepage
- Add a new PHP file named phpinfo.php to the web application root directory
- Inside the phpinfo.php file, add a function to display PHP version information
- Host the vulnerable web application
- Access the web application default homepage
- Access the vulnerable PHP info page


