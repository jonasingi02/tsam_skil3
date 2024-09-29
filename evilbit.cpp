#include <iostream>
#include <cstring>
#include <chrono> 
#include <thread>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>  // For UDP header
#include <arpa/inet.h>    // For inet_addr
#include <unistd.h>       // For close()
#include <errno.h>

struct iphdr {
    unsigned char ihl:4;      
    unsigned char version:4;   
    unsigned char tos;          
    unsigned short tot_len;     
    unsigned short id;         
    unsigned short frag_off;    
    unsigned char ttl;         
    unsigned char protocol;     
    unsigned short check;      
    unsigned int saddr;         
    unsigned int daddr;         
};

struct udphdr {
    unsigned short source;      
    unsigned short dest;        
    unsigned short len;         
    unsigned short check;       
};

unsigned short checksum(void* vdata, size_t length) {
    char* data = (char*)vdata;
    unsigned long acc = 0;
    unsigned short* ptr = (unsigned short*)data;

    for (size_t i = 0; i < length / 2; i++) {
        acc += ntohs(ptr[i]);
    }

    if (length % 2) {
        acc += (ntohs(data[length - 1]) & 0xFF) << 8;
    }

    while (acc >> 16) {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }

    return htons(~acc);
}

int main() {
    const uint32_t signature = htonl(0x5391df19);  // The payload (signature)

    // Create raw socket for sending with IPPROTO_RAW
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
        return 1;
    }

    // Create a standard UDP socket for receiving responses
    int recsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (recsock < 0) {
        std::cerr << "Failed to create receive socket: " << strerror(errno) << std::endl;
        close(sock);
        return 1;
    }

    // Set socket options to allow address reuse
    int optval = 1;
    setsockopt(recsock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    // Bind the receiving socket to the same port (4048) to listen for responses
    struct sockaddr_in recv_addr;
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_addr.s_addr = htonl(INADDR_ANY);  // Accept connections from any IP address
    recv_addr.sin_port = htons(4048);  // Bind to the same port

    if (bind(recsock, (struct sockaddr*)&recv_addr, sizeof(recv_addr)) < 0) {
        std::cerr << "Failed to bind receive socket: " << strerror(errno) << std::endl;
        close(sock);
        close(recsock);
        return 1;
    }

    const char* server_ip = "130.208.246.249";  // Server IP
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(server_ip);
    dest_addr.sin_port = htons(4048);  // Destination port (UDP)

    struct iphdr ip_header;
    ip_header.version = 4;       
    ip_header.ihl = 5;           
    ip_header.tos = 0;           
    ip_header.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(signature)); 
    ip_header.id = htons(54321);   
    ip_header.frag_off = htons(0x8000); 
    ip_header.ttl = 64;           
    ip_header.protocol = IPPROTO_UDP;  
    ip_header.saddr = inet_addr("192.168.1.189");  
    ip_header.daddr = inet_addr(server_ip);  

    struct udphdr udp_header;
    udp_header.source = htons(12345);  
    udp_header.dest = htons(4048);     
    udp_header.len = htons(sizeof(struct udphdr) + sizeof(signature));  
    udp_header.check = 0;  

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

    char pseudo_packet[sizeof(psh) + sizeof(udp_header) + sizeof(signature)];
    memcpy(pseudo_packet, &psh, sizeof(psh));
    memcpy(pseudo_packet + sizeof(psh), &udp_header, sizeof(udp_header));
    memcpy(pseudo_packet + sizeof(psh) + sizeof(udp_header), &signature, sizeof(signature));

    udp_header.check = checksum(pseudo_packet, sizeof(pseudo_packet));

    char packet[sizeof(ip_header) + sizeof(udp_header) + sizeof(signature)];
    memcpy(packet, &ip_header, sizeof(ip_header));  
    memcpy(packet + sizeof(ip_header), &udp_header, sizeof(udp_header));  
    memcpy(packet + sizeof(ip_header) + sizeof(udp_header), &signature, sizeof(signature));  

    ssize_t sent_bytes = sendto(sock, packet, sizeof(packet), 0, 
                                (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    if (sent_bytes < 0) {
        std::cerr << "Failed to send packet: " << strerror(errno) << std::endl;
        close(sock);
        close(recsock);
        return 1;
    }

    std::cout << "Packet sent successfully." << std::endl;


    char recv_buffer[1024];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);

    // Receive the response
    ssize_t recv_bytes = recvfrom(recsock, recv_buffer, sizeof(recv_buffer), 0, 
                                  (struct sockaddr*)&from, &from_len);
    if (recv_bytes < 0) {
        std::cerr << "Failed to receive response: " << strerror(errno) << std::endl;
    } else {
        struct iphdr* recv_ip_header = (struct iphdr*)recv_buffer;
        if (recv_ip_header->protocol == IPPROTO_UDP) {
            struct udphdr* recv_udp_header = (struct udphdr*)(recv_buffer + sizeof(struct iphdr));
            std::cout << "Received response from IP: " << inet_ntoa(from.sin_addr) << std::endl;
            std::cout << "Source Port: " << ntohs(recv_udp_header->source) << std::endl;
            std::cout << "Destination Port: " << ntohs(recv_udp_header->dest) << std::endl;

            // Check if the response matches your criteria
            if (ntohs(recv_udp_header->dest) == 4048 && ntohs(recv_udp_header->source) == 63765) {    
    
                std::cout << "Received expected response from the server." << std::endl;
                std::cout << "Length of the UDP packet: " << ntohs(recv_udp_header->len) << std::endl;
            } else {
                std::cout << "Unexpected response." << std::endl;
            }
        } else {
            std::cout << "Received non-UDP response." << std::endl;
        }
    }

    close(sock);
    close(recsock);
    return 0;
}
