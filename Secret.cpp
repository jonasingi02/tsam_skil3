#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>  // For IP header
#include <arpa/inet.h>   // For inet_addr
#include <unistd.h>      // For close()
#include <vector>

// Secret phrase as an unsigned int (72)
const uint8_t SECRET_NUMBER = 72;  // Convert 72 to network byte order

int main() {
    // List of secret ports to knock
    std::vector<int> secret_ports = {4021};

    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        std::cerr << "Failed to create socket." << std::endl;
        return 1;
    }

    // Server address (replace with the actual server IP)
    const char* server_ip = "130.208.246.249";

    // Set up the server address structure
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    // Send the number 72 to each of the secret ports
    for (int port : secret_ports) {
        server_addr.sin_port = htons(port);  // Set the current port

        // Send the 4-byte unsigned int (72) to the port
        int send_result = sendto(sock, &SECRET_NUMBER, sizeof(SECRET_NUMBER), 0, 
                                 (struct sockaddr*)&server_addr, sizeof(server_addr));
        
        if (send_result < 0) {
            std::cerr << "Failed to send number 72 to port " << port << std::endl;
        } else {
            std::cout << "Number 72 sent to port " << port << std::endl;

            // Wait for a response
            char response[1024];
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);

            // Set a timeout for receiving a response (e.g., 2 seconds)
            struct timeval tv;
            tv.tv_sec = 2;  // 2 seconds timeout
            tv.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            int response_length = recvfrom(sock, response, sizeof(response) - 1, 0, 
                                           (struct sockaddr*)&from, &from_len);
            if (response_length > 0) {
                response[response_length] = '\0';  // Null-terminate the response for printing
                std::cout << "Received response from port " << port << ": " << response << std::endl;
            } else {
                std::cout << "No response received from port " << port << " within the timeout period." << std::endl;
            }
        }
    }

    // Close the socket
    close(sock);
    return 0;
}
