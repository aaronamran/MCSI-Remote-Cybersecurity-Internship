# Write A Standalone Keylogger
A keylogger is a type of malware used in cyberattacks to steal sensitive information by recording keystrokes on a victim's computer. Often installed covertly through phishing emails, it captures login credentials and personal data for attackers to misuse


## References
- [Keystroke Logging](https://en.wikipedia.org/wiki/Keystroke_logging) by Wikipedia
- [GetAsyncKeyState](https://docs.microsoft.com/en-us/windows/desktop/api/winuser/nf-winuser-getasynckeystate) by Microsoft


## Tasks
- Setup a Windows VM
- Write a custom keylogger program with the following capabilities
  - The program starts executing when the system boots
  - The program runs as a background process without affecting any foreground processes
  - The program logs all user keystrokes in hidden files on the same disk
  - The program must use minimal resources to avoid detection
- Keylogger Creation Guidelines
  - You can use Windows APIs in your program
  - Use a programming language of your choice
  - Compile the program into a binary for deployment
- Deploy the keylogger binary in your VM
- Configure the keylogger to execute when the system starts
- Open a web browser and input a fictional username and password into a login form


## Benchmarks
- Validate that your keylogger starts at system boot time
- Validate that your keylogger records all keystrokes in hidden files
- Validate that your keylogger runs as a background process (you can view the active process listing in 'Task Manager')


## Solutions With Scripts
1. 
