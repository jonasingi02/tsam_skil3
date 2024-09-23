#include <iostream>
#include <cstring>      
#include <sys/socket.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>     
#include <cstdlib>      // For atoi()

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <IP address> <low port> <high port>" << std::endl;
        return 1;
    }

    const char* ip_address = argv[1];      // IP address from command line
    int low_port = std::atoi(argv[2]);     // Low port from command line
    int high_port = std::atoi(argv[3]);    // High port from command line

    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }

    // Loop through the port range
    for (int port = low_port; port <= high_port; ++port) {
        // Set up the server address structure
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr)); // Clear the structure
        server_addr.sin_family = AF_INET;             // IPv4
        server_addr.sin_port = htons(port);           // Port number from the loop
        server_addr.sin_addr.s_addr = inet_addr(ip_address); // Server IP from arguments

        const char* message = "Hello";  // Example message

        // Send the message
        int send_result = sendto(sock, message, strlen(message), 0, 
                                 (struct sockaddr*)&server_addr, sizeof(server_addr));

        if (send_result < 0) {
            std::cerr << "Failed to send message to port " << port << std::endl;
            continue; // Skip to the next port
        }

         // Set a timeout for receiving a response
        struct timeval timeout;
        timeout.tv_sec = 2;  // Wait for 2 seconds
        timeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

        // Wait for a response
        char buffer[1024];
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        memset(buffer, 0, sizeof(buffer));  // Clear buffer before receiving

        int recv_len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&from_addr, &from_len);
        if (recv_len < 0) {
            continue;
        } else {
            std::cout << "Received response from port " << port << ": " << std::string(buffer, recv_len) << std::endl;
        }
    }

    // Close the socket
    close(sock);
    return 0;
}
