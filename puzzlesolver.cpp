#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h> 
#include <arpa/inet.h>   
#include <unistd.h>      

// Group details
const uint8_t GROUP_NUMBER = 72;
const uint32_t GROUP_SECRET = 0x96e5f6a7;  // S.E.C.R.E.T signature in host byte order


// Function prototypes
int solve_1(int sock, const char* ip_address, int port);
void solve_2(int sock, const char* ip_address, int port);
void solve_3(int sock, const char* ip_address, int port);
void solve_4(int sock, const char* ip_address, int port);

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
    solve_1(sock1, ip_address, port1);  
    std::cout << std::endl;
    solve_2(sock2, ip_address, port2);  
    std::cout << std::endl;
    solve_3(sock3, ip_address, port3);  
    std::cout << std::endl;
    solve_4(sock4, ip_address, port4);

    // Close the sockets
    close(sock1);
    close(sock2);
    close(sock3);
    close(sock4);

    return 0;
}

// Function to solve puzzle 1
int solve_1(int sock, const char* ip_address, int port) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip_address);
    server_addr.sin_port = htons(port);

    uint32_t signed_challenge = 0x6282cc28;

    // Step 2: Send the 4-byte message (the signature)
    if (sendto(sock, &signed_challenge, sizeof(signed_challenge), 0, 
               (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to send signature to port " << port << std::endl;
        close(sock);
        return 1;
    }
    std::cout << "4-byte signature: " << signed_challenge << "sent to port " << port << std::endl;

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
        std::cout << "Received response from port " << port << ": " << response << std::endl;
    } else {
        std::cout << "No response received from port " << port << " within the timeout period." << std::endl;
    }
    return 1;
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
void solve_3(int sock, const char* ip_address,  int port) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip_address);
    server_addr.sin_port = htons(port);

    // Step 1: Send group number to server
    if (sendto(sock, &GROUP_NUMBER, sizeof(GROUP_NUMBER), 0,
               (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to send group number to port " << port << std::endl;
        return;
    }
    std::cout << "Group number sent to port " << port << std::endl;

    // Step 2: Receive the 4-byte challenge from the server
    uint32_t challenge;
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    
    if (recvfrom(sock, &challenge, sizeof(challenge), 0,
                 (struct sockaddr*)&from_addr, &from_len) < 0) {
        std::cerr << "Failed to receive challenge from port " << port << std::endl;
        return;
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
        return;
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
}



// Function to solve puzzle 4 
void solve_4(int sock, const char* ip_address, int port) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip_address);
    server_addr.sin_port = htons(port);

    std::cout << "Solve puzzle 4 for port " << port << std::endl;

}