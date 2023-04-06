#include "queue.h"
#include "lib.h"
#include "protocols.h"

#include <string.h>
#include <arpa/inet.h>

struct route_table_entry *get_route(struct route_table_entry *rtable, int rtable_len, uint32_t d_addr) {
	uint32_t index = -1;
	for(int i = 0; i < rtable_len; i++)
		if((d_addr & rtable[i].mask) == rtable[i].prefix) {
			if(index == -1)
				index = i;
			else if(ntohl(rtable[index].mask) < ntohl(rtable[i].mask))
				index = i;
		}
	if(index == -1)
		return NULL;
	else return &rtable[index];
}

void send_icmp(char *buf, int send_interface, int type) {
	
	char send_payload[MAX_PACKET_LEN];
	
	//ETH HEADER 
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	uint8_t aux[6] = {0};
	memcpy(aux, eth_hdr->ether_dhost, 6);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, aux, 6);

	//IP HEADER
	// struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	// struct in_addr addr;
	// inet_aton(get_interface_ip(send_interface), addr);
	// ip_hdr->daddr = ip_hdr->saddr;
	// ip_hdr->saddr = addr.s_addr;

	struct icmphdr *icmp_hdr;
	if(type == 3) {

	}

}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	//routing table
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "rtable memory allocation failed");
	int rtable_len = read_rtable(argv[1], rtable);

	//arp tabel
	struct arp_entry *arptable = malloc(60000 * sizeof(struct arp_entry));
	int arptable_len = parse_arp_table("arp_table.txt", arptable);

	uint8_t router_mac[6] = {0};
	uint8_t broadcast_mac[6] = {0};
	memset(broadcast_mac, 0xff, 6);

	// Do not modify this line
	init(argc - 2, argv + 2);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		get_interface_mac(interface, router_mac);
		if(memcmp(eth_hdr->ether_dhost, router_mac, 6) != 0 && memcmp(eth_hdr->ether_dhost, broadcast_mac, 6) != 0) {
			printf("skip\n");
			continue; //wrong destination => drop the package
		}

		if(ntohs(eth_hdr->ether_type) == 0x0800) {
			
			printf("%x ip\n", ntohs(eth_hdr->ether_type));
		
			//IPv4 header
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
			
			//checksum check
			uint16_t initial_checksum = ip_hdr->check;
			ip_hdr->check = 0;
			if(ntohs(initial_checksum) != checksum((u_int16_t *)ip_hdr, sizeof(struct iphdr))) {
				printf("check err");
				continue; //wrong checksum => drop the package
			}

			//TTL check and update
			if(ip_hdr->ttl < 2) {
				//TODO ICMP
				continue;
			}
			else {
				ip_hdr->ttl--;
				ip_hdr->check = 0;
				ip_hdr->check = htons(checksum((u_int16_t *)ip_hdr, sizeof(struct iphdr)));
			}

			//ARP STATIC
			struct route_table_entry *best = get_route(rtable, rtable_len, ip_hdr->daddr);
			int idx = -1;
			for (int i = 0; i < arptable_len; i++) {
				if (arptable[i].ip == best->next_hop)
					idx = i;
			}	

			memcpy(eth_hdr->ether_shost, router_mac, 6);
			memcpy(eth_hdr->ether_dhost, arptable[idx].mac, 6);
			send_to_link(best->interface, buf, len);

		}
		else if (ntohs(eth_hdr->ether_type) == 0x0806)
			printf("%x arp\n", ntohs(eth_hdr->ether_type));
		else
			printf("wrong\n");

	}
}

