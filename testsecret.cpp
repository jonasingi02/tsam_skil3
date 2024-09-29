#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>  // For IP header
#include <arpa/inet.h>   // For inet_addr, htons, htonl
#include <unistd.h>      // For close()

// Group number (first byte)
const uint8_t GROUP_NUMBER = 72;

// Secret provided by the server (replace with the actual value received)
const uint32_t GROUP_SECRET = 0x96e5f6a7;

int main() {
    // Server address and port (replace with the actual values)
    const char* server_ip = "130.208.246.249";
    int target_port = 4047;

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
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_port = htons(target_port);

    // Step 1: Send the group number (1 byte)
    uint8_t group_number = GROUP_NUMBER;
    if (sendto(sock, &group_number, sizeof(group_number), 0, 
               (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to send group number to port " << target_port << std::endl;
        close(sock);
        return 1;
    }
    std::cout << "Group number sent to port " << target_port << std::endl;

    // Step 2: Receive the 4-byte challenge
    uint32_t challenge;
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    
    if (recvfrom(sock, &challenge, sizeof(challenge), 0, 
                 (struct sockaddr*)&from_addr, &from_len) < 0) {
        std::cerr << "Failed to receive challenge from port " << target_port << std::endl;
        close(sock);
        return 1;
    }
   
    
    // Convert the challenge to host byte order (since it was received in network byte order)
    challenge = ntohl(challenge);
    std::cout << "Received challenge: 0x" << std::hex << challenge << std::endl;

    // Step 3: XOR the challenge with your group's secret (0x96e5f6a7)
    uint32_t signed_challenge = challenge ^ GROUP_SECRET;

    // Step 4: Convert the signed challenge to network byte order
    signed_challenge = htonl(signed_challenge);
        
    // Step 5: Prepare the 5-byte response (group number + signed challenge)
    uint8_t response[5];
    response[0] = GROUP_NUMBER;  // First byte: group number
    memcpy(response + 1, &signed_challenge, sizeof(signed_challenge));  // Next 4 bytes: signed challenge

    // Step 6: Send the signed challenge to the server
    if (sendto(sock, response, sizeof(response), 0, 
               (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to send signed challenge to port " << target_port << std::endl;
    } else {
        std::cout << "Signed challenge sent to port " << target_port << std::endl;
    }

    // Optional: Wait for confirmation response from the server
    char confirmation[1024];
    int response_length = recvfrom(sock, confirmation, sizeof(confirmation) - 1, 0, 
                                   (struct sockaddr*)&from_addr, &from_len);
    if (response_length > 0) {
        confirmation[response_length] = '\0';  // Null-terminate the response for printing
        std::cout << "Received response from port " << target_port << ": " << confirmation << std::endl;
    } else {
        std::cout << "No response received from port " << target_port << " within the timeout period." << std::endl;
    }

    // Close the socket
    close(sock);
    return 0;
}