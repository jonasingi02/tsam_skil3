#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>  // For UDP header
#include <arpa/inet.h>    // For inet_addr
#include <unistd.h>       // For close()
#include <errno.h>

// Function to calculate the checksum
unsigned short checksum(void* vdata, size_t length) {
    char* data = (char*)vdata;
    unsigned long acc = 0;
    unsigned short* ptr = (unsigned short*)data;

    // Sum all 16-bit words
    for (size_t i = 0; i < length / 2; i++) {
        acc += ntohs(ptr[i]);
    }

    // If the length is odd, add the last byte
    if (length % 2) {
        acc += (ntohs(data[length - 1]) & 0xFF) << 8;
    }

    // Fold acc down to 16 bits
    while (acc >> 16) {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }

    return htons(~acc);
}

int main() {
    const uint32_t signature = htonl(0x5391df19);  // The payload (signature)

    // Create raw socket for sending with IPPROTO_UDP
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
        return 1;
    }

    // Destination address
    const char* server_ip = "130.208.246.249";  // Server IP
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(server_ip);
    dest_addr.sin_port = htons(4048);  // Destination port (UDP)

    // Create IP header
    struct iphdr ip_header;
    ip_header.version = 4;        // IPv4
    ip_header.ihl = 5;            // Header length (5 words)
    ip_header.tos = 0;            // Type of Service
    ip_header.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(signature));  // Total length (IP header + UDP header + payload)
    ip_header.id = htons(54321);   // Identification
    ip_header.frag_off = htons(0x8000);  // Don't fragment
    ip_header.ttl = 64;           // Time to live
    ip_header.protocol = IPPROTO_UDP;  // UDP protocol
    ip_header.saddr = inet_addr("172.18.100.90");  // Source IP (change to your machine's IP)
    ip_header.daddr = inet_addr(server_ip);  // Destination IP

    // Create UDP header
    struct udphdr udp_header;
    udp_header.source = htons(12345);  // Source port
    udp_header.dest = htons(4048);     // Destination port
    udp_header.len = htons(sizeof(struct udphdr) + sizeof(signature));  // Length of UDP header + data
    udp_header.check = 0;  // Checksum (optional, can be left as 0 for simplicity)

    // Create a pseudo-header for UDP checksum calculation
    struct pseudo_header {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_len;
    } psh;

    psh.src_addr = ip_header.saddr;
    psh.dst_addr = ip_header.daddr;
    psh.zero = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_len = udp_header.len;

    // Buffer to hold the pseudo-header, UDP header, and data for checksum
    char pseudo_packet[sizeof(psh) + sizeof(udp_header) + sizeof(signature)];
    memcpy(pseudo_packet, &psh, sizeof(psh));
    memcpy(pseudo_packet + sizeof(psh), &udp_header, sizeof(udp_header));
    memcpy(pseudo_packet + sizeof(psh) + sizeof(udp_header), &signature, sizeof(signature));

    // Calculate UDP checksum
    udp_header.check = checksum(pseudo_packet, sizeof(pseudo_packet));

    // Buffer to hold the final packet (IP header + UDP header + data)
    char packet[sizeof(ip_header) + sizeof(udp_header) + sizeof(signature)];
    memcpy(packet, &ip_header, sizeof(ip_header));   // Copy IP header into the packet
    memcpy(packet + sizeof(ip_header), &udp_header, sizeof(udp_header));  // Copy UDP header
    memcpy(packet + sizeof(ip_header) + sizeof(udp_header), &signature, sizeof(signature));  // Copy payload (signature)

    // Send the packet
    ssize_t sent_bytes = sendto(sock, packet, sizeof(packet), 0, 
                                (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    if (sent_bytes < 0) {
        std::cerr << "Failed to send packet: " << strerror(errno) << std::endl;
        close(sock);
        return 1;
    }

    std::cout << "Packet sent successfully." << std::endl;

    // Set timeout for receiving the response (e.g., 1 seconds)
    struct timeval tv;
    tv.tv_sec = 1;  
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Buffer for receiving response
    char recv_buffer[1024];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);

    // Receive the response
    ssize_t recv_bytes = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0, 
                                  (struct sockaddr*)&from, &from_len);
    if (recv_bytes < 0) {
        std::cerr << "Failed to receive response: " << strerror(errno) << std::endl;
    } else {
        std::cout << "Received response from IP: " << inet_ntoa(from.sin_addr) << std::endl;

        // Print out the raw response in hex format
        std::cout << "Raw response (hex): ";
        for (ssize_t i = 0; i < recv_bytes; ++i) {
            printf("%02x ", (unsigned char)recv_buffer[i]);
        }
        std::cout << std::endl;

        // Optionally parse the response if it's UDP or ICMP
        struct iphdr* recv_ip_header = (struct iphdr*)recv_buffer;
        if (recv_ip_header->protocol == IPPROTO_UDP) {
            struct udphdr* recv_udp_header = (struct udphdr*)(recv_buffer + sizeof(struct iphdr));
            std::cout << "UDP packet received." << std::endl;
            std::cout << "Source Port: " << ntohs(recv_udp_header->source) << std::endl;
            std::cout << "Destination Port: " << ntohs(recv_udp_header->dest) << std::endl;
        }
    }

    // Close the socket
    close(sock);

    return 0;
}
