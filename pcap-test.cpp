#include <pcap.h>
#include <bits/stdc++.h>
#include <libnet.h>
using namespace std;



struct pac{
	libnet_ethernet_hdr ethernet_hdr;
	libnet_ipv4_hdr ipv4_hdr;
	libnet_tcp_hdr tcp_hdr;
};


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};


void print_addr(in_addr addr) {
	printf("%d.%d.%d.%d\n", addr.s_addr & 0xff, (addr.s_addr >> 8) & 0xff, (addr.s_addr >> 16) & 0xff, (addr.s_addr >> 24) & 0xff);
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		pac *info = (pac*)packet;
		// if not ipv4, or tcp, skip.
		if (info->ethernet_hdr.ether_type != htons(ETHERTYPE_IP)) continue;
		if (info->ipv4_hdr.ip_p != IPPROTO_TCP) continue;


		// print souce MAC, destination MAC, source IP, destination IP, source port, destination port
		// source, destination MAC
		cout << "source MAC: ";
		for (int i = 0; i < 6; i++) {
			printf("%02x", info->ethernet_hdr.ether_shost[i]);
			if (i != 5) cout << ":";
		}
		cout << endl;
		cout << "destination MAC: ";
		for (int i = 0; i < 6; i++) {
			printf("%02x", info->ethernet_hdr.ether_dhost[i]);
			if (i != 5) cout << ":";
		}
		cout << endl;

		// source, destination  IP
	
		cout << "source IP: ";
		print_addr(info->ipv4_hdr.ip_src);
		cout << endl;
		cout << "destination IP: ";
		print_addr(info->ipv4_hdr.ip_dst);
		cout << endl;

		// source, destination port
		cout << "source port: " << ntohs(info->tcp_hdr.th_sport) << endl;
		cout << "destination port: " << ntohs(info->tcp_hdr.th_dport) << endl;
		cout << endl;

		// print packet's payload's hexadecimal value, upto 8 bytes.
		cout << "payload: ";
		for (int i = 0; i < 8; i++) {
			printf("%02x", packet[sizeof(pac) + i]);
			if (i != 7) cout << ":";
		}
		cout << endl;
	}

	pcap_close(pcap);
}
