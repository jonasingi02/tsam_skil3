#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>  // For IP header
#include <arpa/inet.h>   // For inet_addr
#include <unistd.h>      // For close()

// Group number (first byte)
const uint8_t GROUP_NUMBER = 72;

// Two constants to XOR
const uint32_t FIRST_NUMBER = 0xc57429be;
const uint32_t SECOND_NUMBER = 0x96e5f6a7;

int main() {
    // Calculate XOR of the two numbers
    uint32_t xor_result = FIRST_NUMBER ^ SECOND_NUMBER;

    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        std::cerr << "Failed to create socket." << std::endl;
        return 1;
    }

    // Server address (replace with the actual server IP)
    const char* server_ip = "130.208.246.249";
    int target_port = 4021;

    // Set up the server address structure
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_port = htons(target_port);  // Set the target port

    // Prepare the buffer to send (5 bytes: 1 byte for the group number and 4 bytes for the XOR result)
    uint8_t buffer[5];
    buffer[0] = GROUP_NUMBER;  // First byte is the group number

    // Convert the XOR result to network byte order (big-endian) and copy into the buffer
    uint32_t xor_network_order = htonl(xor_result);
    memcpy(buffer + 1, &xor_network_order, sizeof(xor_network_order));

    // Send the 5-byte message to the target port
    int send_result = sendto(sock, buffer, sizeof(buffer), 0, 
                             (struct sockaddr*)&server_addr, sizeof(server_addr));
    
    if (send_result < 0) {
        std::cerr << "Failed to send message to port " << target_port << std::endl;
    } else {
        std::cout << "Message sent to port " << target_port << ": group number (" 
                  << static_cast<int>(GROUP_NUMBER) << "), XOR result ("
                  << std::hex << xor_result << ")" << std::endl;

        // Prepare to receive a response
        char response[1024];  // Buffer to hold the response
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);

        // Set a timeout for receiving a response (e.g., 2 seconds)
        struct timeval tv;
        tv.tv_sec = 2;  // 2 seconds timeout
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // Wait for a response
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
