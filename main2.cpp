#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#define TELNET_PORT 23
#define SNAP_LEN 1518
#define SIZE_ETHERNET 14

// Global variables for cleanup
pcap_t *handle = NULL;
int sockfd = -1;
volatile sig_atomic_t running = 1;

// Packet processing callback function
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct ip *ip_header;
    const struct tcphdr *tcp_header;
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    
    // Skip Ethernet header
    ip_header = (struct ip*)(packet + SIZE_ETHERNET);
    int size_ip = ip_header->ip_hl * 4;
    
    // Get TCP header
    tcp_header = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
    
    // Convert IP addresses to string format
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
    
    printf("Packet captured - Source: %s:%d -> Destination: %s:%d\n",
           source_ip, ntohs(tcp_header->source),
           dest_ip, ntohs(tcp_header->dest));
}

// Signal handler for graceful shutdown
void signal_handler(int signum) {
    running = 0;
}

// Initialize Telnet connection
int init_telnet(const char *hostname, int port) {
    struct sockaddr_in server_addr;
    struct hostent *server;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        return -1;
    }
    
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "Error resolving hostname\n");
        return -1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    server_addr.sin_port = htons(port);
    
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error connecting to server");
        return -1;
    }
    
    return 0;
}

// Initialize packet capture
pcap_t* init_pcap(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp port 23";  // Capture only Telnet traffic
    bpf_u_int32 net, mask;
    
    // Get network number and mask
    if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", interface);
        net = 0;
        mask = 0;
    }
    
    // Open capture device
    handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        return NULL;
    }
    
    // Compile and apply the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return NULL;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return NULL;
    }
    
    return handle;
}

// Send Telnet command
int send_telnet_command(const char *command) {
    if (sockfd < 0) return -1;
    
    if (send(sockfd, command, strlen(command), 0) < 0) {
        perror("Error sending command");
        return -1;
    }
    
    // Send carriage return and newline
    const char *crlf = "\r\n";
    if (send(sockfd, crlf, strlen(crlf), 0) < 0) {
        perror("Error sending CRLF");
        return -1;
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <telnet_host>\n", argv[0]);
        return 1;
    }
    
    // Set up signal handler
    signal(SIGINT, signal_handler);
    
    // Initialize Telnet connection
    if (init_telnet(argv[2], TELNET_PORT) < 0) {
        fprintf(stderr, "Failed to initialize Telnet connection\n");
        return 1;
    }
    
    // Initialize packet capture
    if (init_pcap(argv[1]) == NULL) {
        fprintf(stderr, "Failed to initialize packet capture\n");
        close(sockfd);
        return 1;
    }
    
    printf("Starting packet capture. Press Ctrl+C to stop.\n");
    
    // Main loop
    char command[256];
    while (running) {
        printf("Enter command (or 'quit' to exit): ");
        if (fgets(command, sizeof(command), stdin) == NULL) break;
        
        // Remove newline
        command[strcspn(command, "\n")] = 0;
        
        if (strcmp(command, "quit") == 0) break;
        
        // Send command
        if (send_telnet_command(command) < 0) {
            fprintf(stderr, "Failed to send command\n");
            break;
        }
        
        // Capture some packets
        pcap_dispatch(handle, 10, packet_handler, NULL);
    }
    
    // Cleanup
    if (handle) pcap_close(handle);
    if (sockfd >= 0) close(sockfd);
    
    return 0;
}