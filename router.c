#include "queue.h"
#include "lib.h"
#include "protocols.h"

#include <string.h>
#include <arpa/inet.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

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
	int send_payload_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;
	
	//ETH HEADER 
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	uint8_t aux_mac[6] = {0};
	memcpy(aux_mac, eth_hdr->ether_dhost, 6);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, aux_mac, 6);

	//IP HEADER
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	uint32_t aux_ip = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = aux_ip;
	ip_hdr->tot_len = send_payload_len;
	ip_hdr->ttl = 64;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((u_int16_t *)ip_hdr, sizeof(struct iphdr)));
	ip_hdr->protocol = 1;

	//ICMP HEADER
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((u_int16_t *)icmp_hdr, sizeof(struct icmphdr)));


	//ASSAMBLE PACKAGE
	memcpy(send_payload, eth_hdr, sizeof(struct ether_header));
	memcpy(send_payload + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
	memcpy(send_payload + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));
	memcpy(ip_hdr + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr + sizeof(struct iphdr), 64);

	send_to_link(send_interface, send_payload, send_payload_len);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	//routing table
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "rtable memory allocation failed");
	int rtable_len = read_rtable(argv[1], rtable);

	//arp table
	struct arp_entry *arptable = malloc(60000 * sizeof(struct arp_entry));
	int arptable_len = parse_arp_table("arp_table.txt", arptable);

	uint8_t mac[6] = {0};
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

		get_interface_mac(interface, mac);
		if(memcmp(eth_hdr->ether_dhost, mac, 6) != 0 && memcmp(eth_hdr->ether_dhost, broadcast_mac, 6) != 0) {
			printf("skip\n");
			continue; //wrong destination => drop the package
		}

		if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			
			printf("%x ip\n", ntohs(eth_hdr->ether_type));
		
			//IPv4 header
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
			
			if(ip_hdr->daddr == inet_addr(get_interface_ip(interface)) && ip_hdr->protocol == 1) {
				struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				if(icmp_hdr->type == 8) {
					send_icmp(buf, interface, 0);
					continue;
				}
			}

			//checksum check
			uint16_t initial_checksum = ip_hdr->check;
			ip_hdr->check = 0;
			if(ntohs(initial_checksum) != checksum((u_int16_t *)ip_hdr, sizeof(struct iphdr))) {
				printf("checksum err\n");
				continue; //wrong checksum => drop the package
			}

			//TTL check and update
			if(ip_hdr->ttl < 2) {
				send_icmp(buf, interface, 11);
				printf("time excedeed\n");
				continue;
			}
			else {
				ip_hdr->ttl--;
				ip_hdr->check = 0;
				ip_hdr->check = htons(checksum((u_int16_t *)ip_hdr, sizeof(struct iphdr)));
			}

			//////////////////////ARP STATIC//////////////////////////
			struct route_table_entry *best = get_route(rtable, rtable_len, ip_hdr->daddr);
			if(best == NULL) {
				send_icmp(buf, interface, 3);
				continue;
			}
			int idx = -1;
			for (int i = 0; i < arptable_len; i++) {
				if (arptable[i].ip == best->next_hop)
					idx = i;
				}	

			//printf("%d\n", idx);
			memcpy(eth_hdr->ether_shost, mac, 6);
			memcpy(eth_hdr->ether_dhost, arptable[idx].mac, 6);
			send_to_link(best->interface, buf, len);
			//////////////////////////////////////////////////////////

		}
		else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)
			printf("%x arp\n", ntohs(eth_hdr->ether_type));
		else
			printf("wrong\n");

	}
}

