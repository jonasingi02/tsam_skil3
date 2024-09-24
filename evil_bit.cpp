#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>  // For IP header
#include <arpa/inet.h>   // For inet_addr
#include <unistd.h>      // For close()
#include <stdint.h>      // For uint32_t

// Function to create an IPv4 header with the reserved bit set to 1
struct iphdr create_ip_header(uint32_t dest_ip) {
    struct iphdr header;

    // Version and IHL (Header Length)
    header.version = 4;  // IPv4
    header.ihl = 5;      // Header length is 5 words (20 bytes)

    // Type of Service (ToS)
    header.tos = 0;

    // Total Length (header + data)
    header.tot_len = htons(sizeof(struct iphdr) + sizeof(uint32_t));  // IP header + data length

    // Identification
    header.id = htons(54321);  // Arbitrary ID for this example

    // Flags and Fragment Offset
    // Set the reserved bit to 1 (0x8000 means reserved = 1)
    header.frag_off = htons(0x4000);  // Set reserved bit in the flags

    // Time to Live (TTL)
    header.ttl = 64;  // Common default TTL valuet

    // Protocol (UDP)
    header.protocol = IPPROTO_UDP;

    // Source IP address (0.0.0.0 for this example)
    header.saddr = inet_addr("0.0.0.0");  // Use local address

    // Destination IP address
    header.daddr = dest_ip;  // Set to destination IP

    return header;
}

int main() {
    // The signature to send (4 bytes)
    const uint32_t signature = htonl(0x5391df19);  // Convert to network byte order

    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        std::cerr << "Failed to create socket." << std::endl;
        return 1;
    }

    // Server address (replace with the actual server IP)
    const char* server_ip = "130.208.246.249";  // Change this to the correct IP if necessary

    // Set up the server address structure
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_port = htons(4052);  // Set the port to 4052

    // Create the IPv4 header
    struct iphdr ip_header = create_ip_header(server_addr.sin_addr.s_addr);

    // Send the IPv4 header + signature to the server
    char buffer[sizeof(iphdr) + sizeof(signature)];
    memcpy(buffer, &ip_header, sizeof(ip_header));  // Copy the IP header into the buffer
    memcpy(buffer + sizeof(ip_header), &signature, sizeof(signature));  // Copy the signature

    // Send the buffer to the server
    int send_result = sendto(sock, buffer, sizeof(buffer), 
                             0, (struct sockaddr*)&server_addr, sizeof(server_addr));
    
    if (send_result < 0) {
        std::cerr << "Failed to send signature to port 4052." << std::endl;
    } else {
        std::cout << "Signature sent to port 4052." << std::endl;

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
            std::cout << "Received response from port 4052: " << response << std::endl;
        } else {
            std::cout << "No response received from port 4052 within the timeout period." << std::endl;
        }
    }

    // Close the socket
    close(sock);
    return 0;
}
