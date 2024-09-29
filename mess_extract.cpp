#include <iostream>
#include <arpa/inet.h>  // For ntohl, ntohs (network-to-host byte order conversion)

int main() {
    // Example: The last 6 bytes (in network byte order)
    unsigned char last_bytes[6] = { 0x3f, 0x2a, 0x3d, 0xd9, 0x4a, 0x4a };  // ?*=d9J in hex

    // First 4 bytes represent the IP address in network order
    unsigned int ip_addr;
    memcpy(&ip_addr, last_bytes, 4);
    ip_addr = ntohl(ip_addr);  // Convert from network byte order to host byte order

    // Last 2 bytes represent the port number in network order
    unsigned short port;
    memcpy(&port, last_bytes + 4, 2);
    port = ntohs(port);  // Convert from network byte order to host byte order

    // Convert IP address from integer to readable format
    struct in_addr ip_struct;
    ip_struct.s_addr = ip_addr;
    char* ip_str = inet_ntoa(ip_struct);

    // Output the extracted information
    std::cout << "Extracted IP Address: " << ip_str << std::endl;
    std::cout << "Extracted Port: " << port << std::endl;

    return 0;
}