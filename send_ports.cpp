#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>  // For IP header
#include <arpa/inet.h>   // For inet_addr
#include <unistd.h>      // For close()
#include <vector>

int main() {
    // The list of secret ports
    std::vector<int> secret_ports = {4021, 4033, 4052, 4074};

    // Create the secret phrase as a comma-separated string of the secret ports
    std::string secret_phrase;
    for (size_t i = 0; i < secret_ports.size(); ++i) {
        secret_phrase += std::to_string(secret_ports[i]);
        if (i != secret_ports.size() - 1) {
            secret_phrase += ",";  // Add a comma after each port, except the last one
        }
    }

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

    // We're sending the message to port 4074
    int target_port = 4074;
    server_addr.sin_port = htons(target_port);  // Set the port to 4074

    // Buffer to hold the knock message (only the secret phrase)
    char buffer[1024];

    // Copy the secret phrase (comma-separated ports) into the buffer
    strcpy(buffer, secret_phrase.c_str());

    // Send the knock message to port 4074
    int send_result = sendto(sock, buffer, secret_phrase.length(), 0, 
                             (struct sockaddr*)&server_addr, sizeof(server_addr));
    
    if (send_result < 0) {
        std::cerr << "Failed to send knock to port " << target_port << std::endl;
    } else {
        std::cout << "Knock sent to port " << target_port << " with secret phrase: " << secret_phrase << std::endl;

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
            std::cout << "Received response from port " << target_port << ": " << response << std::endl;
        } else {
            std::cout << "No response received from port " << target_port << " within the timeout period." << std::endl;
        }
    }

    // Close the socket
    close(sock);
    return 0;
}
