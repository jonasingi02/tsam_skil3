#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>  // For IP header
#include <arpa/inet.h>   // For inet_addr, htons
#include <unistd.h>      // For close()

const char* SERVER_IP = "130.208.246.249";  // Replace with your server's IP

void send_udp_message(int sock, const char* message, int target_port) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(target_port);  // Port number for this puzzle

    // Send the UDP message to the target port
    if (sendto(sock, message, strlen(message), 0, 
               (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to send message to port " << target_port << std::endl;
        return;
    }
    std::cout << "Message sent to port " << target_port << ": " << message << std::endl;

    // Prepare to receive a response
    char response[1024];  // Buffer to hold the response
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    // Set a timeout for receiving a response (optional)
    struct timeval tv;
    tv.tv_sec = 2;  // 2 seconds timeout
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Wait for a response from the server
    int response_length = recvfrom(sock, response, sizeof(response) - 1, 0, 
                                   (struct sockaddr*)&from_addr, &from_len);
    if (response_length > 0) {
        response[response_length] = '\0';  // Null-terminate the response for printing
        std::cout << "Received response from port " << target_port << ": " << response << std::endl;
    } else {
        std::cout << "No response received from port " << target_port << " within the timeout period." << std::endl;
    }
}

int main() {
    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        std::cerr << "Failed to create socket." << std::endl;
        return 1;
    }

    // Example UDP message (could be any required string, integer, etc.)
    const char* udp_message = "Hello, this is a UDP message!";

    // Send the message to different puzzle ports and receive responses
    send_udp_message(sock, udp_message, 4047);  // Send message to port 4033
    send_udp_message(sock, udp_message, 4048);  // Send message to port 4052
    send_udp_message(sock, udp_message, 4059);  // Send message to port 4074
    send_udp_message(sock, udp_message, 4066);

    // Close the socket
    close(sock);

    return 0;
}