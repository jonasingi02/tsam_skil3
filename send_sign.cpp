#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>  // For IP header
#include <arpa/inet.h>   // For inet_addr, htons, htonl
#include <unistd.h>      // For close()

int main() {
    // Define your S.E.C.R.E.T signature (replace with the correct value from your TA)
    const uint32_t SECRET_SIGNATURE = 0x5391df19;  // Replace with the correct signature
    
    // Server address and port (replace with actual values if needed)
    const char* server_ip = "130.208.246.249";  // Replace with the actual IP if needed
    int target_port = 4033;  // Port 4033

    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        std::cerr << "Failed to create socket." << std::endl;
        return 1;
    }

    // Set up the server address structure
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);  // Server IP
    server_addr.sin_port = htons(target_port);  // Port 4033

    // Step 1: Convert the S.E.C.R.E.T signature to network byte order (big-endian)
    uint32_t signature_network_order = htonl(SECRET_SIGNATURE);  // Convert to network byte order

    // Step 2: Send the 4-byte message (the signature)
    if (sendto(sock, &signature_network_order, sizeof(signature_network_order), 0, 
               (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to send signature to port " << target_port << std::endl;
        close(sock);
        return 1;
    }
    std::cout << "4-byte signature sent to port " << target_port << std::endl;

    // Step 3: Prepare to receive a response
    char response[1024];  // Buffer to hold the response
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    // Set a timeout for receiving a response (optional)
    struct timeval tv;
    tv.tv_sec = 2;  // 2 seconds timeout
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Step 4: Wait for a response from the server
    int response_length = recvfrom(sock, response, sizeof(response) - 1, 0, 
                                   (struct sockaddr*)&from_addr, &from_len);
    if (response_length > 0) {
        response[response_length] = '\0';  // Null-terminate the response for printing
        std::cout << "Received response from port " << target_port << ": " << response << std::endl;
    } else {
        std::cout << "No response received from port " << target_port << " within the timeout period." << std::endl;
    }

    // Close the socket
    close(sock);
    return 0;
}