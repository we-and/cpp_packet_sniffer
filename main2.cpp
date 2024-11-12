#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <ctype.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#define TELNET_PORT 23
#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define MAX_INTERFACES 64
#define IAC     255  // Interpret As Command
#define DONT    254
#define DO      253
#define WONT    252
#define WILL    251
#define SB      250  // Start subcommand
#define SE      240  // End subcommand

// Global variables for cleanup
pcap_t *handle = NULL;
int sockfd = -1;
volatile sig_atomic_t running = 1;
char server_ip[INET_ADDRSTRLEN] = {0}; 
// Structure to store interface information
typedef struct {
    char name[256];
    char description[256];
    char ip[INET_ADDRSTRLEN];
} InterfaceInfo;
// ... [previous includes and definitions remain the same] ...
// ... [previous includes and definitions remain the same] ...

// Function to list available interfaces
InterfaceInfo* list_interfaces(int* count) {
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    InterfaceInfo* interfaces = (InterfaceInfo*)malloc(MAX_INTERFACES * sizeof(InterfaceInfo));
    *count = 0;
    
    // Retrieve the device list
    if(pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        free(interfaces);
        return NULL;
    }
    
    // Print the list and store in our array
    for(d = alldevs; d && *count < MAX_INTERFACES; d = d->next) {
        strcpy(interfaces[*count].name, d->name);
        
        if (d->description) {
            strcpy(interfaces[*count].description, d->description);
        } else {
            interfaces[*count].description[0] = '\0';  // Empty string for no description
        }
        
        // Get IP address
        pcap_addr_t *a;
        interfaces[*count].ip[0] = '\0';  // Initialize to empty string
        for(a = d->addresses; a; a = a->next) {
            if(a->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
                inet_ntop(AF_INET, &sin->sin_addr, interfaces[*count].ip, INET_ADDRSTRLEN);
                break;
            }
        }
        
        printf("%d. %s\n", *count + 1, interfaces[*count].name);
        if (interfaces[*count].description[0] != '\0') {
            printf("   Description: %s\n", interfaces[*count].description);
        }
        if (interfaces[*count].ip[0] != '\0') {
            printf("   IP address: %s\n", interfaces[*count].ip);
        }
//        printf("\n");
        
        (*count)++;
    }
    
    // Free the device list
    pcap_freealldevs(alldevs);
    
    return interfaces;
}
void print_payload(const u_char *payload, int len, int is_server) {
    if (len <= 0) return;
    
    // Print direction indicator
    printf("%s ", is_server ? "Server>" : "Client>");
    
    // Print the actual content
    for(int i = 0; i < len; i++) {
        if(isprint(payload[i]) || payload[i] == '\n' || payload[i] == '\r') {
            putchar(payload[i]);
            if(payload[i] == '\n' || payload[i] == '\r') {
                // Add direction indicator after newline
                printf("%s ", is_server ? "Server>" : "Client>");
            }
        }
    }
    fflush(stdout);
}
// Enhanced packet handler with payload processing
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    
    // Skip Ethernet header
    ip_header = (struct ip*)(packet + SIZE_ETHERNET);
    int size_ip = ip_header->ip_hl * 4;
    
    // Get TCP header
    tcp_header = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
    int size_tcp = tcp_header->th_off * 4;
    
    // Get payload
    const u_char *payload = packet + SIZE_ETHERNET + size_ip + size_tcp;
    int size_payload = ntohs(ip_header->ip_len) - (size_ip + size_tcp);
    
    // Convert IP addresses
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
    
    if (size_payload > 0) {
        // Determine if the packet is from server or client
        char source_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
        
        // Compare with stored server IP
        int is_server = (strcmp(source_ip, server_ip) == 0);
        
        print_payload(payload, size_payload, is_server);
    }
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
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <telnet_host>\n", argv[0]);
        return 1;
    }
    
    // List available interfaces
    int interface_count;
    InterfaceInfo* interfaces = list_interfaces(&interface_count);
    
    if (!interfaces || interface_count == 0) {
        fprintf(stderr, "No interfaces found or error listing interfaces\n");
        return 1;
    }
    
    // Let user select an interface
    int selected;
    do {
        printf("Select interface (1-%d): ", interface_count);
        if (scanf("%d", &selected) != 1 || selected < 1 || selected > interface_count) {
            printf("Invalid selection. Please try again.\n");
            // Clear input buffer
            while (getchar() != '\n');
            continue;
        }
        break;
    } while (1);
    
    // Clear input buffer
    while (getchar() != '\n');
    
    printf("Selected interface: %s\n", interfaces[selected-1].name);
    
    // Set up signal handler
    signal(SIGINT, signal_handler);
    
    // Initialize Telnet connection
    if (init_telnet(argv[1], TELNET_PORT) < 0) {
        fprintf(stderr, "Failed to initialize Telnet connection\n");
        free(interfaces);
        return 1;
    }
    
    // Initialize packet capture
    if (init_pcap(interfaces[selected-1].name) == NULL) {
        fprintf(stderr, "Failed to initialize packet capture\n");
        close(sockfd);
        free(interfaces);
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
    free(interfaces);
    
    return 0;
}