// #include <iostream>
// #include <cstring>
// #include <sys/socket.h>
// #include <netinet/ip.h>  // For IP header
// #include <netinet/udp.h> // For UDP header
// #include <arpa/inet.h>   // For inet_addr
// #include <unistd.h>      // For close()
// #include <cstdlib>

// // Define some constants
// #define IP_MAXPACKET 65535

// // Function to calculate the checksum (RFC 1071)
// unsigned short checksum(void* b, int len) {
//     unsigned short* buf = (unsigned short*)b;
//     unsigned int sum = 0;
//     unsigned short result;

//     for (sum = 0; len > 1; len -= 2)
//         sum += *buf++;
//     if (len == 1)
//         sum += *(unsigned char*)buf;
//     sum = (sum >> 16) + (sum & 0xFFFF);
//     sum += (sum >> 16);
//     result = ~sum;
//     return result;
// }

// int main() {
//     // Create a raw socket
//     int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
//     if (sock < 0) {
//         std::cerr << "Failed to create raw socket. Are you root?" << std::endl;
//         return 1;
//     }

//     // Packet buffer to hold the packet
//     char packet[IP_MAXPACKET];
//     memset(packet, 0, IP_MAXPACKET);  // Zero out the packet buffer

//     // IP header
//     struct iphdr* ip_header = (struct iphdr*)packet;
//     ip_header->ihl = 5;  // Internet Header Length (5 * 4 = 20 bytes)
//     ip_header->version = 4;  // IPv4
//     ip_header->tos = 0;  // Type of Service (set to 0)
    
//     // Set the "evil bit" - we'll simulate it using the last bit of the "tos" field
//     ip_header->tos |= 0x80;  // Set the highest bit (bit 7 of the TOS field)
    
//     ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);  // Total length
//     ip_header->id = htons(54321);  // Random identifier
//     ip_header->frag_off = 0;  // No fragmentation
//     ip_header->ttl = 255;  // Time to live
//     ip_header->protocol = IPPROTO_UDP;  // UDP protocol
//     ip_header->check = 0;  // Checksum (initially set to 0)
//     ip_header->saddr = inet_addr("89.17.146.12");  // Source IP (replace with your actual source)
//     ip_header->daddr = inet_addr("130.208.246.249");  // Destination IP

//     // UDP header
//     struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct iphdr));
//     udp_header->source = htons(12345);  // Source port
//     udp_header->dest = htons(4012);     // Destination port
//     udp_header->len = htons(sizeof(struct udphdr));  // UDP header length
//     udp_header->check = 0;  // UDP checksum (set to 0)

//     // Calculate IP checksum
//     ip_header->check = checksum(packet, ip_header->tot_len);

//     // Destination address structure
//     struct sockaddr_in dest;
//     dest.sin_family = AF_INET;
//     dest.sin_port = htons(4052);  // Port 4012
//     dest.sin_addr.s_addr = inet_addr("130.208.246.249");  // Destination IP

//     // Send the packet
//     if (sendto(sock, packet, ip_header->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
//         std::cerr << "Failed to send packet" << std::endl;
//         close(sock);
//         return 1;
//     }

//     // Wait for a response
//     char buffer[1024];
//     struct sockaddr_in from;
//     socklen_t from_len = sizeof(from);

//     // Set a timeout for receiving response
//     struct timeval tv;
//     tv.tv_sec = 5;  // 2 seconds timeout
//     tv.tv_usec = 0;
//     setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

//     int response_length = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&from, &from_len);
//     if (response_length > 0) {
//         // Successfully received a response
//         buffer[response_length] = '\0';  // Null-terminate the response for printing
//         std::cout << "Received response: " << buffer << std::endl;
//     } else {
//         // No response received
//         std::cout << "No response received within the timeout period." << std::endl;
//     }

//     // Close the socket
//     close(sock);
//     return 0;
// }


#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>  // For IP header
#include <arpa/inet.h>   // For inet_addr
#include <unistd.h>      // For close()
#include <vector>

// Your S.E.C.R.E.T signature (4 bytes)
const uint32_t SECRET_SIGNATURE = htonl(0x12345678); // Example signature

// Secret phrase to send (replace with your actual phrase)
const char* SECRET_PHRASE = "open_sesame";  // Example phrase

int main() {
    // List of secret ports to knock
    std::vector<int> secret_ports = {4021, 4033, 4052, 4074};

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

    // Buffer to hold the knock message (signature + secret phrase)
    char buffer[1024];
    
    // Copy the S.E.C.R.E.T signature into the buffer
    memcpy(buffer, &SECRET_SIGNATURE, sizeof(SECRET_SIGNATURE));

    // Copy the secret phrase right after the signature in the buffer
    strcpy(buffer + sizeof(SECRET_SIGNATURE), SECRET_PHRASE);

    // Send the knock message to each of the secret ports
    for (int port : secret_ports) {
        server_addr.sin_port = htons(port);  // Set the current port

        int send_result = sendto(sock, buffer, sizeof(SECRET_SIGNATURE) + strlen(SECRET_PHRASE), 
                                 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
        
        if (send_result < 0) {
            std::cerr << "Failed to send knock to port " << port << std::endl;
        } else {
            std::cout << "Knock sent to port " << port << std::endl;

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

