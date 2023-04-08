#include "queue.h"
#include "lib.h"
#include "protocols.h"

#include <string.h>
#include <arpa/inet.h>

#define ETHERTYPE_IP htons(0x0800)
#define ETHERTYPE_ARP htons(0x0806)
#define ARP_REQUEST htons(1)
#define ARP_REPLY htons(2)
#define HLEN 6 //length of hardware addr (MAC)

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
	
	//ETH HEADER UPDATE
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	uint8_t aux_mac[HLEN] = {0};
	memcpy(aux_mac, eth_hdr->ether_dhost, HLEN);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, HLEN);
	memcpy(eth_hdr->ether_shost, aux_mac, HLEN);

	//IP HEADER UPDATE
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	uint32_t aux_ip = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = aux_ip;
	ip_hdr->tot_len = send_payload_len;
	ip_hdr->ttl = 64;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((u_int16_t *)ip_hdr, sizeof(struct iphdr)));
	ip_hdr->protocol = 1;

	//ICMP HEADER UPDATE
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((u_int16_t *)icmp_hdr, sizeof(struct icmphdr)));


	//ASSAMBLE PACKAGE
	memcpy(send_payload, eth_hdr, sizeof(struct ether_header));
	memcpy(send_payload + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
	memcpy(send_payload + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));
	//memcpy(ip_hdr + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr + sizeof(struct iphdr), 64);

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
	struct arp_entry *arptable = malloc(100 * sizeof(struct arp_entry));
	DIE(arptable == NULL, "arptable memory allocation failed");
	int arptable_len = 0;

	//packet queue
	queue packet_q = queue_create();

	uint8_t mac[HLEN] = {0};
	uint8_t broadcast_mac[HLEN] = {0};
	memset(broadcast_mac, 0xff, HLEN);

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
		printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		printf("DEST: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
		printf("SURSA: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);

		//CHECK DESTINATION, IF DESTINATION IS WRONG -> DROP PACKAGE
		if(memcmp(eth_hdr->ether_dhost, mac, HLEN) != 0 && memcmp(eth_hdr->ether_dhost, broadcast_mac, HLEN) != 0) {
			printf("skip\n");
			continue;
		}

		if(eth_hdr->ether_type == ETHERTYPE_IP) {
			
			printf("%x ip\n\n", ntohs(eth_hdr->ether_type));
		
			//IPv4 header
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
			
			//ICMP ECHO REQUEST
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

			//find best route to send the packet
			struct route_table_entry *best_route = get_route(rtable, rtable_len, ip_hdr->daddr);
			if(best_route == NULL) {
				send_icmp(buf, interface, 3);
				continue;
			}
			uint8_t route_mac[HLEN];
			get_interface_mac(best_route->interface, route_mac);

			//find entry in ARP table
			int arp_index = -1;
			for (int i = 0; i < arptable_len; i++) {
				if (arptable[i].ip == best_route->next_hop) {
					arp_index = i;
					break;
				}
			}

			//entry not found in ARP table
			if(arp_index == -1) {
				//queue the packet and send ARP request
				char *buf_copy = malloc(MAX_PACKET_LEN);
				memcpy(buf_copy, buf, len);
				queue_enq(packet_q, buf_copy);
				
				//ETHER HEADER
				struct ether_header *arp_eth_hdr = malloc(sizeof(struct ether_header));
				memcpy(arp_eth_hdr->ether_dhost, broadcast_mac, HLEN);
				memcpy(arp_eth_hdr->ether_shost, route_mac, HLEN);
				arp_eth_hdr->ether_type = ETHERTYPE_ARP;

				//ARP HEADER
				struct arp_header *arp_hdr = malloc(sizeof(struct arp_header));
				arp_hdr->htype = htons(1); //ETHERNET type
				arp_hdr->ptype = ETHERTYPE_IP;
				arp_hdr->hlen = HLEN;
				arp_hdr->plen = 4;
				arp_hdr->op = ARP_REQUEST;
				memcpy(arp_hdr->tha, broadcast_mac, HLEN);
				memcpy(arp_hdr->sha, route_mac, HLEN);
				arp_hdr->tpa = best_route->next_hop;
				arp_hdr->spa = inet_addr(get_interface_ip(best_route->interface));

				//prepare ARP request
				char arp_request[MAX_PACKET_LEN];
				memcpy(arp_request, arp_eth_hdr, sizeof(struct ether_header));
				memcpy(arp_request + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));
				send_to_link(best_route->interface, arp_request, sizeof(struct ether_header) + sizeof(struct arp_header));
			}
			else {
				memcpy(eth_hdr->ether_shost, route_mac, HLEN);
				memcpy(eth_hdr->ether_dhost, arptable[arp_index].mac, HLEN);
				send_to_link(best_route->interface, buf, len);
			}
		}
		else if (eth_hdr->ether_type == ETHERTYPE_ARP) {
		
			printf("%x arp\n\n", ntohs(eth_hdr->ether_type));
		
			//ARP HEADER
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
		
			//RECEIVED ARP REQUEST FOR THE ROUTER MAC ADDR
			if(arp_hdr->op == ARP_REQUEST && arp_hdr->tpa == inet_addr(get_interface_ip(interface))) {

				//ETH HEADER UPDATE
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, HLEN);
				memcpy(eth_hdr->ether_shost, mac, HLEN);

				//ARP HEADER UPDATE
				memcpy(arp_hdr->tha, arp_hdr->sha, HLEN);
				memcpy(arp_hdr->sha, mac, HLEN);

				u_int32_t aux_ip = arp_hdr->tpa;
				arp_hdr->tpa = arp_hdr->spa;
				arp_hdr->spa = aux_ip;

				arp_hdr->op = ARP_REPLY;
				send_to_link(interface, buf, len);
			}
			//RECEIVED ARP REPLY 
			else if(arp_hdr->op == ARP_REPLY && arp_hdr->tpa == inet_addr(get_interface_ip(interface))) {
				
				//create new entry for the ARP table
				struct arp_entry *new_arp_entry = malloc(sizeof(struct arp_entry));
				memcpy(new_arp_entry->mac, arp_hdr->sha, HLEN);
				new_arp_entry->ip = arp_hdr->spa;

				//insert the new entry in the ARP table
				arptable[arptable_len] = *new_arp_entry;
				arptable_len++;

				//send packets that are waiting in queue
				while(queue_empty(packet_q) == 0) {
					char *packet = (char *)queue_deq(packet_q);

					//get packet headers
					struct ether_header *pkt_eth_hdr = (struct ether_header *) packet;
					struct iphdr *pkt_ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

					//find route and send the packet
					struct route_table_entry *best_route = get_route(rtable, rtable_len, pkt_ip_hdr->daddr);

					int arp_index = -1;
					for (int i = 0; i < arptable_len; i++) {
						if (arptable[i].ip == best_route->next_hop) {
							arp_index = i;
							break;
						}
					}
					memcpy(pkt_eth_hdr->ether_dhost, arptable[arp_index].mac, HLEN);
					send_to_link(best_route->interface, packet, len);
				}
			}
		}
		else printf("wrong\n");
	}
}