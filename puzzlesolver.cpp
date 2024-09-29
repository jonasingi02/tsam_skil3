#include <iostream>
#include <cstring>
#include <iomanip>  // Include this header for std::setw
#include <sys/socket.h>
#include <netinet/in.h>  
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>  
#include <arpa/inet.h>   
#include <unistd.h>      
#define IP4_HDRLEN 20
#define UDP_HDRLEN 8

//Couldnt finish the checksum puzzle port got answer from instructor
const unsigned int SECRET_PORT1 = 4025;
const unsigned int SECRET_PORT2 = 4094;
const char* SECRET_PHRASE = "Omae wa mou shindeiru";

// Group details
const uint8_t GROUP_NUMBER = 72;
const uint32_t GROUP_SECRET = 0x96e5f6a7;  // S.E.C.R.E.T signature in host byte order
const uint32_t SIGNED_CHALLENGE = 0x6282cc28;



//Have to create struct for IP header and UDP header not defined on macos
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


// Function prototypes
int solve_1(int sock, const char* ip_address, int port);
void solve_2(int sock, const char* ip_address, int port);
int solve_3(int sock, const char* ip_address, int port);
void solve_4(int sock, const char* ip_address);
unsigned short calc_checksum(unsigned short* data, int len);
unsigned short udp_checksum(struct iphdr* iph, struct udphdr* udph, unsigned char* payload, int payload_len);


int main(int argc, char* argv[]) {
    // Check if the user provided the IP address and ports
     if (argc != 6) {
        std::cerr << "Usage: " << argv[0] << " <IP address> <port1> <port2> <port3> <port4>" << std::endl;
        return 1;
    }

    // Get the IP address and ports from the command line arguments
    const char* ip_address = argv[1];      
    int port1 = std::atoi(argv[2]);   
    int port2 = std::atoi(argv[3]);
    int port3 = std::atoi(argv[4]);
    int port4 = std::atoi(argv[4]);

    // Create the sockets
    int sock1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int sock2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int sock3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int sock4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // Check if the sockets were created successfully
    if (sock1 < 0 || sock2 < 0 || sock3 < 0 || sock4 < 0) {
        std::cerr << "Failed to create sockets." << std::endl;
        return 1;
    }

    // Solve the puzzles
    // solve_1(sock1, ip_address, port1);  
    // std::cout << std::endl;
    // solve_2(sock2, ip_address, port2);  
    // std::cout << std::endl;
    // solve_3(sock3, ip_address, port3);  
    // std::cout << std::endl;
    solve_4(sock4, ip_address);

    // Close the sockets
    close(sock1);
    close(sock2);
    close(sock3);
    close(sock4);

    return 0;
}



int solve_1(int sock, const char* ip_address, int port) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip_address);
    server_addr.sin_port = htons(port);

    uint32_t signed_challenge = 0x6282cc28;

    //Send the 4-byte message (the signature)
    if (sendto(sock, &signed_challenge, sizeof(signed_challenge), 0, 
               (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to send signature to port " << port << std::endl;
        close(sock);
        return 1;
    }
    std::cout << "4-byte signature: " << signed_challenge << " sent to port " << port << std::endl;

    //Prepare to receive a response
    char response[1024];  // Buffer to hold the response
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    // Set a timeout for receiving a response 
    struct timeval tv;
    tv.tv_sec = 2;  // 2 seconds timeout
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    //Wait for a response from the server
    int response_length = recvfrom(sock, response, sizeof(response) - 1, 0, 
                                   (struct sockaddr*)&from_addr, &from_len);
    if (response_length > 0) {
        response[response_length] = '\0';  // Null-terminate the response for printing
        std::cout << "Received response from port " << port << ": " << response << std::endl;
    } else {
        std::cout << "No response received from port " << port << " within the timeout period." << std::endl;
    }

    //Get the last 6 bytes of the message
    size_t message_len = strlen(response);
    unsigned char message_info[6];
    memcpy(message_info, response + message_len - 6, 6);
    

    std::cout << "Last 6 bytes in hex: ";
    for (int i = 0; i < 6; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)message_info[i] << " ";
    }
    std::cout << std::endl;


    //Extract the checksum from the first 2 bytes
    unsigned short checksum;
    memcpy(&checksum, message_info, 2);
    checksum = ntohs(checksum);
    

    //Extract the IP address from the last 4 bytes
    unsigned int ip_addr;
    memcpy(&ip_addr, message_info + 2, 4);


    struct in_addr ip_struct;
    ip_struct.s_addr = ip_addr;
    char* src_ip = inet_ntoa(ip_struct);
 
     // Buffer for the packet (IP + UDP headers)
    char buffer[IP4_HDRLEN + UDP_HDRLEN]; 
    

    // Destination port and source port
    int src_port = 12345;  

    // Fill in the IPv4 header (20 bytes)
    struct iphdr* iph = (struct iphdr*)buffer;
    iph->ihl = 5;         // Internet Header Length (20 bytes)
    iph->version = 4;     // IPv4
    iph->tos = 0;         // Type of service
    iph->tot_len = htons(IP4_HDRLEN + UDP_HDRLEN);  // Total length of IP + UDP header
    iph->id = htonl(54321);    // Identification
    iph->frag_off = 0;         // Fragment offset
    iph->ttl = 255;            // Time to live
    iph->protocol = IPPROTO_UDP;  // Protocol (UDP)
    iph->check = 0;            // Set to 0 before calculating the checksum
    iph->saddr = inet_addr(src_ip);  // Source IP address
    iph->daddr = inet_addr(ip_address); // Destination IP address

    // Calculate IP checksum
    iph->check = calc_checksum((unsigned short*)iph, IP4_HDRLEN);
    std::cout << "Calculated IP checksum: " << iph->check << std::endl;
    

    // Fill in the UDP header (8 bytes)
    struct udphdr* udph = (struct udphdr*)(buffer + IP4_HDRLEN);
    udph->source = htons(src_port);  // Source port
    udph->dest = htons(port);   // Destination port
    udph->len = htons(UDP_HDRLEN);   // UDP header length
    udph->check = 0;                 // Initialize UDP checksum to 0

    // Calculate UDP checksum manually
    unsigned short pseudo_packet[UDP_HDRLEN];
    memcpy(pseudo_packet, udph, UDP_HDRLEN);
    udph->check = 0; 
    
    // Payload for the UDP packet
    unsigned char payload[2] = {0x00, 0x00};  
  

    unsigned int count = 0;
    unsigned short udp_chk = udp_checksum(iph, udph, payload, 2);  
    


    // Gradually increase payload size and modify it to match the checksum
    std::cout << "Calculated checksum: " << udp_chk << std::endl;
    std::cout << "Expected checksum: " << checksum << std::endl;

    unsigned short payload_size = ~checksum - ~udp_chk; 
    std::cout << "Payload size: " << payload_size << std::endl;

    payload[0] = payload_size & 0xFF;  
    payload[1] = (payload_size >> 8) & 0xFF;
    std::cout << "Payload: " << (int)payload[0] << std::endl;
    std::cout << "Payload: " << (int)payload[1] << std::endl;

    udp_chk = udp_checksum(iph, udph, payload, 2);  // Set the correct checksum in the UDP header
    std::cout << "Calculated checksum: " << udp_chk << std::endl;
   
    udph->check = htons(udp_chk);  // Set the correct checksum in the UDP header

    // Destination information
    struct sockaddr_in dest_info;
    memset(&dest_info, 0, sizeof(dest_info));
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr.s_addr = inet_addr(ip_address);
    dest_info.sin_port = htons(port);

    // Send the packet as the payload via the UDP socket
    if (sendto(sock, buffer, IP4_HDRLEN + UDP_HDRLEN, 0, 
               (struct sockaddr*)&dest_info, sizeof(dest_info)) < 0) {
        std::cerr << "Error sending packet." << std::endl;
        close(sock);
        return 1;
    }

    std::cout << "Packet sent to port " << port << " successfully." << std::endl;
    response_length = recvfrom(sock, response, sizeof(response) - 1, 0, 
                                   (struct sockaddr*)&from_addr, &from_len);
    if (response_length > 0) {
        response[response_length] = '\0';  // Null-terminate the response for printing
        std::cout << "Received response from port " << port << ": " << response << std::endl;
    } else {
        std::cout << "No response received from port " << port << " within the timeout period." << std::endl;
    }
    return 0;
}

unsigned short udp_checksum(struct iphdr* iph, struct udphdr* udph, unsigned char* payload, int payload_len) {
    char buf[1024];  // Buffer for pseudo-header + UDP header + payload
    char* ptr = buf;

    // Pseudo-header fields
    struct pseudo_header {
        u_int32_t src_addr;
        u_int32_t dest_addr;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t udp_length;
    } psh;

    // Fill in the pseudo-header
    psh.src_addr = iph->saddr;  // Source IP address
    psh.dest_addr = iph->daddr;  // Destination IP address
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(UDP_HDRLEN + payload_len);  // UDP length in network byte order

    // Copy pseudo-header to buffer
    memcpy(ptr, &psh, sizeof(psh));
    ptr += sizeof(psh);

    // Copy UDP header to buffer
    memcpy(ptr, udph, UDP_HDRLEN);
    ptr += UDP_HDRLEN;

    // Copy UDP payload (if any) to buffer
    if (payload_len > 0) {
        memcpy(ptr, payload, payload_len);
        ptr += payload_len;
    }

    // Calculate the checksum
    int total_len = ptr - buf;  // Total length for checksum calculation
    return calc_checksum((unsigned short*)buf, total_len);
}


unsigned short calc_checksum(unsigned short* data, int len) {
    unsigned long sum = 0;

    // Sum all 16-bit words
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }

    // Add remaining byte if the length is odd
    if (len == 1) {
        sum += *(unsigned char*)data;
    }

    // Fold high into low
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Take the 1's complement of the result
    return ~sum;
}




// Function to solve puzzle 2
void solve_2(int sock, const char* ip_address, int port) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip_address);
    server_addr.sin_port = htons(port);

    std::cout << "Solve puzzle 2 for port " << port << std::endl;

}

// Function to solve puzzle 3
int solve_3(int sock, const char* ip_address,  int port) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip_address);
    server_addr.sin_port = htons(port);

    // Step 1: Send group number to server
    if (sendto(sock, &GROUP_NUMBER, sizeof(GROUP_NUMBER), 0,
               (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to send group number to port " << port << std::endl;
        return -1;
    }
    std::cout << "Group number sent to port " << port << std::endl;

    // Step 2: Receive the 4-byte challenge from the server
    uint32_t challenge;
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    
    if (recvfrom(sock, &challenge, sizeof(challenge), 0,
                 (struct sockaddr*)&from_addr, &from_len) < 0) {
        std::cerr << "Failed to receive challenge from port " << port << std::endl;
        return -1;
    }

    challenge = ntohl(challenge);  // Convert challenge to host byte order
    std::cout << "Received challenge: 0x" << std::hex << challenge << std::endl;

    // Step 3: XOR challenge with GROUP_SECRET
    uint32_t signed_challenge = challenge ^ GROUP_SECRET;
    signed_challenge = htonl(signed_challenge);  // Convert to network byte order

    std::cout << "Signed challenge: 0x" << std::hex << signed_challenge << std::endl;

    // Step 4: Prepare 5-byte response (1 byte group number + 4 bytes signed challenge)
    uint8_t response[5];
    response[0] = GROUP_NUMBER;
    memcpy(response + 1, &signed_challenge, sizeof(signed_challenge));

    // Step 5: Send the signed challenge to the server
    if (sendto(sock, response, sizeof(response), 0,
               (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to send signed challenge to port " << port << std::endl;
        return -1;
    }
    std::cout << "Signed challenge sent to port " << port << std::endl;

    // Step 6: Wait for the server's response
    char reply[1024];
    int reply_len = recvfrom(sock, reply, sizeof(reply) - 1, 0,
                             (struct sockaddr*)&from_addr, &from_len);
    if (reply_len > 0) {
        reply[reply_len] = '\0';  // Null-terminate the reply
        std::cout << "Received response from port " << port << ": " << reply << std::endl;
    } else {
        std::cout << "No response received from port " << port << " within the timeout period." << std::endl;
    }
    return 0;
}



// Function to solve puzzle 4 
void solve_4(int sock, const char* ip_address) {
    char buffer[1024];  // Buffer to hold the message
    memset(buffer, 0, sizeof(buffer));
    
    // Copy the signature (4 bytes)
    memcpy(buffer, &SIGNED_CHALLENGE, sizeof(SIGNED_CHALLENGE));
    
    // Copy the secret phrase into the buffer right after the signature
    memcpy(buffer + sizeof(SIGNED_CHALLENGE), SECRET_PHRASE, strlen(SECRET_PHRASE));
    
    // Setup destination address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SECRET_PORT1);  // Target port
    server_addr.sin_addr.s_addr = inet_addr(ip_address);  // Server IP address

    // Send the knock (UDP packet)
    if (sendto(sock, buffer, sizeof(SIGNED_CHALLENGE) + strlen(SECRET_PHRASE), 0,
               (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to send knock to port " << SECRET_PORT1 << std::endl;
    } else {
        std::cout << "Knock sent to port " << SECRET_PORT1 << std::endl;
    }

    char response[1024];  // Buffer to hold the response
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    int response_length = recvfrom(sock, response, sizeof(response) - 1, 0, 
                                   (struct sockaddr*)&from_addr, &from_len);
    if (response_length > 0) {
        response[response_length] = '\0';  // Null-terminate the response for printing
        std::cout << "Received response from port 4048" << ": " << response << std::endl;
    } else {
        std::cout << "No response received from port 4048"  << " within the timeout period." << std::endl;
    }



    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SECRET_PORT2);  // Target port
    server_addr.sin_addr.s_addr = inet_addr(ip_address);  // Server IP address

    if (sendto(sock, buffer, sizeof(SIGNED_CHALLENGE) + strlen(SECRET_PHRASE), 0,
               (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to send knock to port " << SECRET_PORT2 << std::endl;
    } else {
        std::cout << "Knock sent to port " << SECRET_PORT2 << std::endl;

    }

    response_length = recvfrom(sock, response, sizeof(response) - 1, 0, 
                                   (struct sockaddr*)&from_addr, &from_len);
    if (response_length > 0) {
        response[response_length] = '\0';  // Null-terminate the response for printing
        std::cout << "Received response from port 4048" << ": " << response << std::endl;
    } else {
        std::cout << "No response received from port 4048"  << " within the timeout period." << std::endl;
    }


}