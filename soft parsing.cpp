#include <pcap.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <regex> 
#include <unordered_map> 
#include <thread> 
#include <mutex> 
#include <fstream> 

std::unordered_map<std::string, std::string> phoneNumberToClient;
std::mutex mutex; 
std::ofstream outputFile; 

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void analyze_packet(const u_char* packet, int packet_length);

int main() {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Не удается открыть сетевой интерфейс: %s\n", errbuf);
        return 1;
    }
    phoneNumberToClient["+123456789"] = "Клиент1";
    phoneNumberToClient["+987654321"] = "Клиент2";
    outputFile.open("results.txt", std::ios::out);

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    outputFile.close();

    return 0;
}

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    std::thread(analyze_packet, packet, pkthdr->len).detach();
}

void analyze_packet(const u_char* packet, int packet_length) {
    const struct ip* ip_header = (struct ip*)(packet + 14);  
    const struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl << 2)); 
    uint16_t dest_port = ntohs(tcp_header->th_dport);
    const u_char* packet_data = packet + 14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2); 
    int data_length = packet_length - (14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));
    std::regex phoneRegex("\\+\\d{9,12}");

    std::string packetData(reinterpret_cast<const char*>(packet_data), data_length);
    std::smatch match;
    while (std::regex_search(packetData, match, phoneRegex)) {
        std::string phoneNumber = match[0];
        auto it = phoneNumberToClient.find(phoneNumber);
        if (it != phoneNumberToClient.end()) {
            std::string clientName = it->second;
            std::cout << "Найден номер телефона: " << phoneNumber << " Клиент банка: " << clientName << std::endl;

            // Запишем результат в файл (с блокировкой мьютексом для безопасности)
            std::lock_guard<std::mutex> lock(mutex);
            outputFile << "Найден номер телефона: " << phoneNumber << " Клиент банка: " << clientName << std::endl;
        }
        packetData = match.suffix();
    }
}
