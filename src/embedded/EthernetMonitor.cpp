#include <iostream>
#include <vector>
#include <deque>
#include <mutex>
#include <thread>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
// #include <pcap.h> // Assuming raw sockets or libpcap for Ethernet capture

// Configuration
const int LISTEN_PORT = 8002; // Port to receive requests from Central Processor
const size_t MAX_BUFFER_SIZE = 100000; // Store last 100k packets

struct EthPacket {
    uint64_t gptp_timestamp_ns;
    std::vector<uint8_t> payload;
};

std::deque<EthPacket> packet_buffer;
std::mutex buffer_mutex;

// Simulated gPTP Timestamping
uint64_t get_gptp_timestamp_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// Thread 1: Continuously capture Ethernet traffic and timestamp it
void capture_ethernet_traffic() {
    std::cout << "[EthMonitor] Starting Ethernet capture..." << std::endl;
    
    // In a real scenario, use libpcap or AF_PACKET raw sockets here.
    // For demonstration, we simulate incoming packets.
    while (true) {
        usleep(1000); // Simulate 1ms packet arrival
        
        EthPacket pkt;
        pkt.gptp_timestamp_ns = get_gptp_timestamp_ns();
        pkt.payload = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}; // Dummy payload (e.g., SOME/IP or DoIP)

        std::lock_guard<std::mutex> lock(buffer_mutex);
        packet_buffer.push_back(pkt);
        
        if (packet_buffer.size() > MAX_BUFFER_SIZE) {
            packet_buffer.pop_front();
        }
    }
}

// Thread 2: Listen for requests from Central Processor and send back data
void handle_processor_requests() {
    int server_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_DGRAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(LISTEN_PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    std::cout << "[EthMonitor] Listening for Central Processor requests on port " << LISTEN_PORT << "..." << std::endl;

    char buffer[1024] = {0};
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    while (true) {
        int valread = recvfrom(server_fd, buffer, 1024, 0, (struct sockaddr*)&client_addr, &client_len);
        if (valread > 0) {
            // Expecting request format: [Start_TS:8][End_TS:8]
            uint64_t start_ts, end_ts;
            memcpy(&start_ts, buffer, sizeof(uint64_t));
            memcpy(&end_ts, buffer + sizeof(uint64_t), sizeof(uint64_t));

            std::cout << "[EthMonitor] Received request for time window: " 
                      << start_ts << " to " << end_ts << std::endl;

            // Filter packets
            std::vector<EthPacket> matched_packets;
            {
                std::lock_guard<std::mutex> lock(buffer_mutex);
                for (const auto& pkt : packet_buffer) {
                    if (pkt.gptp_timestamp_ns >= start_ts && pkt.gptp_timestamp_ns <= end_ts) {
                        matched_packets.push_back(pkt);
                    }
                }
            }

            std::cout << "[EthMonitor] Found " << matched_packets.size() << " packets. Sending to Central Processor..." << std::endl;
            
            // Send back (Simplified: sending count and first packet TS as proof)
            uint32_t count = matched_packets.size();
            sendto(server_fd, &count, sizeof(count), 0, (struct sockaddr*)&client_addr, client_len);
        }
    }
}

int main() {
    std::thread capture_thread(capture_ethernet_traffic);
    std::thread request_thread(handle_processor_requests);

    capture_thread.join();
    request_thread.join();

    return 0;
}
