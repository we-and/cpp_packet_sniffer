#include <pcap.h>
#include <iostream>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cctype>

class PacketMonitor {
private:
    pcap_t* handle;
    
    static void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
        // Get IP header - on macOS, we need to handle BSD-style packets
        const struct ip* ip_header;
        int ethernet_header_length = 14;
        
        // Check if we're capturing on 'any' device or loopback
        if (pcap_datalink((pcap_t*)user_data) == DLT_NULL) {
            ip_header = (struct ip*)(packet + 4); // BSD loopback encapsulation
            ethernet_header_length = 4;
        } else {
            ip_header = (struct ip*)(packet + ethernet_header_length);
        }
        
        // Get TCP header
        int ip_header_len = ip_header->ip_hl * 4;
        const struct tcphdr* tcp_header = (struct tcphdr*)(packet + ethernet_header_length + ip_header_len);
        
        // Get payload
        int tcp_header_len = tcp_header->th_off * 4;
        const u_char* payload = packet + ethernet_header_length + ip_header_len + tcp_header_len;
        int payload_len = pkthdr->len - (ethernet_header_length + ip_header_len + tcp_header_len);
        
        std::cout << "\n=== Telnet Packet ===" << std::endl;
        std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
        std::cout << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;
        std::cout << "Source Port: " << ntohs(tcp_header->th_sport) << std::endl;
        std::cout << "Destination Port: " << ntohs(tcp_header->th_dport) << std::endl;
        std::cout << "Payload length: " << payload_len << " bytes" << std::endl;
        
        if (payload_len > 0) {
            std::cout << "Payload (ASCII): ";
            for (int i = 0; i < payload_len; i++) {
                if (isprint(payload[i])) {
                    std::cout << payload[i];
                } else {
                    printf("\\x%02x", payload[i]);
                }
            }
            std::cout << std::endl;
        }
    }

public:
    PacketMonitor() : handle(nullptr) {}
    
    void list_interfaces() {
        pcap_if_t *alldevs;
        char errbuf[PCAP_ERRBUF_SIZE];
        
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            std::cerr << "Error finding devices: " << errbuf << std::endl;
            return;
        }
        
        std::cout << "Available interfaces:" << std::endl;
        for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
            std::cout << "Interface: " << d->name << std::endl;
            if (d->description) {
                std::cout << "Description: " << d->description << std::endl;
            }
            
            // Print addresses
            for (pcap_addr_t *a = d->addresses; a != nullptr; a = a->next) {
                if (a->addr && a->addr->sa_family == AF_INET) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, 
                             &((struct sockaddr_in*)a->addr)->sin_addr,
                             ip, sizeof(ip));
                    std::cout << "  IP address: " << ip << std::endl;
                }
            }
            std::cout << std::endl;
        }
        
        pcap_freealldevs(alldevs);
    }
    
    bool initialize(const char* interface) {
        char errbuf[PCAP_ERRBUF_SIZE];
        
        std::cout << "Opening interface: " << interface << std::endl;
        
        // Open the network interface for packet capture
        handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            std::cerr << "Error opening interface: " << errbuf << std::endl;
            return false;
        }
        
        // Set filter to capture telnet traffic
        struct bpf_program fp;
        const char* filter = "tcp port 23";
        if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
            return false;
        }
        
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
            return false;
        }
        
        std::cout << "Successfully initialized capture on " << interface << std::endl;
        return true;
    }
    
    void start_capture() {
        if (handle == nullptr) {
            std::cerr << "Packet capture not initialized" << std::endl;
            return;
        }
        
        std::cout << "Starting packet capture... (Press Ctrl+C to stop)" << std::endl;
        pcap_loop(handle, 0, packet_handler, (u_char*)handle);
    }
    
    ~PacketMonitor() {
        if (handle) {
            pcap_close(handle);
        }
    }
};

int main(int argc, char* argv[]) {
    if (geteuid() != 0) {
        std::cerr << "This program requires root privileges to capture packets" << std::endl;
        return 1;
    }
    
    PacketMonitor monitor;
    
    // List all interfaces first
    monitor.list_interfaces();
    
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>" << std::endl;
        std::cerr << "Example: " << argv[0] << " lo0" << std::endl;
        return 1;
    }
    
    if (!monitor.initialize(argv[1])) {
        return 1;
    }
    
    monitor.start_capture();
    return 0;
}