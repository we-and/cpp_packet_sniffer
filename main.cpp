#include <iostream>
#include <string>
#include <thread>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

#define TELNET_PORT 23
#define PACKET_BUFFER_SIZE 1024
#define PCAP_SNAPLEN 65535 // Max packet size
#define PCAP_TIMEOUT 1000  // Capture timeout in ms

// Telnet connection
int connectToTelnet(const std::string& ip) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TELNET_PORT);
    inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Telnet connection failed");
        close(sock);
        return -1;
    }

    std::cout << "Connected to Telnet server at " << ip << std::endl;
    return sock;
}

// Send a command over Telnet
void sendTelnetCommand(int sock,  std::string& command) {
    command = command + "\r\n"; // Telnet commands end with CRLF
    if (send(sock, command.c_str(), command.length(), 0) < 0) {
        perror("Telnet send failed");
    }
}

// Packet capture callback
void packetHandler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    std::cout << "Packet captured! Length: " << header->len << " bytes" << std::endl;
    // Process packet data here...
}

// Start packet sniffing on the given interface
void startSniffing(const std::string& iface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface.c_str(), PCAP_SNAPLEN, 1, PCAP_TIMEOUT, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device " << iface << ": " << errbuf << std::endl;
        return;
    }

    // Set a basic filter (optional)
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Could not set filter on device " << iface << std::endl;
    }

    std::cout << "Starting packet capture on " << iface << std::endl;
    pcap_loop(handle, 0, packetHandler, nullptr);

    pcap_close(handle);
}

int main() {
    std::string telnetIp ="localhost";;// "192.168.1.10"; // Replace with your Telnet server IP
    std::string iface = "eth0"; // Replace with your network interface

    // Connect to Telnet
    int telnetSock = connectToTelnet(telnetIp);
    if (telnetSock < 0) return -1;

    // Start packet sniffing in a separate thread
    std::thread sniffingThread(startSniffing, iface);

    // Send Telnet commands in the main thread
    std::string command;
    while (true) {
        std::cout << "Enter Telnet command: ";
        std::getline(std::cin, command);
        if (command == "exit") break;
        sendTelnetCommand(telnetSock, command);
    }

    // Close Telnet socket
    close(telnetSock);

    // Stop packet sniffing
    pcap_breakloop(nullptr);
    sniffingThread.join();

    std::cout << "Program terminated." << std::endl;
    return 0;
}