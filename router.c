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

//comparator for sorting the rtable by (prefix & mask) firstly and mask secondly
int rtable_cmp(const void *a, const void *b) {
	struct route_table_entry *r1 = (struct route_table_entry *) a;
	struct route_table_entry *r2 = (struct route_table_entry *) b;

	if (ntohl(r1->prefix & r1->mask) == ntohl(r2->prefix & r2->mask))
		return (ntohl(r1->mask) - ntohl(r2->mask));
	else 
		return (ntohl(r1->prefix & r1->mask) - ntohl(r2->prefix & r2->mask));
}

//LPM algorithm using binary search to find the best route
struct route_table_entry *get_route(struct route_table_entry *rtable, int rtable_len, uint32_t d_addr) {
	int left = 0, right = rtable_len - 1, mid;
	struct route_table_entry *best_route = NULL;

	while(right - left >= 0) {
		mid = (left + right) / 2;
		if (ntohl(rtable[mid].prefix & rtable[mid].mask) < ntohl(d_addr & rtable[mid].mask))
			left = mid + 1;
		else if (ntohl(rtable[mid].prefix & rtable[mid].mask) > ntohl(d_addr & rtable[mid].mask))
			right = mid - 1;
		//if we find a match we will continue the binary search for the right part of the rtable
		//in order to find a match with a bigger mask
		else {
			best_route = rtable + mid;
			left = mid + 1;
		}
	}
	return best_route;
}

void send_icmp(char *buf, int send_interface, int type) {
	
	char send_payload[MAX_PACKET_LEN];
	int send_payload_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	
	//update ETH HEADER
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	uint8_t aux_mac[HLEN] = {0};
	memcpy(aux_mac, eth_hdr->ether_dhost, HLEN);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, HLEN);
	memcpy(eth_hdr->ether_shost, aux_mac, HLEN);

	//update IP HEADER
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	uint32_t aux_ip = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = aux_ip;
	ip_hdr->tot_len = send_payload_len;
	ip_hdr->ttl = 64;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((u_int16_t *)ip_hdr, sizeof(struct iphdr)));
	ip_hdr->protocol = 1;

	//update ICMP HEADER
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((u_int16_t *)icmp_hdr, sizeof(struct icmphdr)));


	//assamble the package
	memcpy(send_payload, eth_hdr, sizeof(struct ether_header));
	memcpy(send_payload + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
	memcpy(send_payload + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));

	//send the package back
	send_to_link(send_interface, send_payload, send_payload_len);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	//routing table
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "rtable memory allocation failed");
	int rtable_len = read_rtable(argv[1], rtable);
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), rtable_cmp);

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
		printf("DESTINATION: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
		printf("SOURCE: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);

		//check destination, if destination is wrong -> drop the package
		if(memcmp(eth_hdr->ether_dhost, mac, HLEN) != 0 && memcmp(eth_hdr->ether_dhost, broadcast_mac, HLEN) != 0) {
			printf("Wrong destination skipping.......\n\n");
			continue;
		}

		//check package type (IP/ARP)
		if(eth_hdr->ether_type == ETHERTYPE_IP) {
			
			printf("TYPE: %d ip\n\n", ntohs(eth_hdr->ether_type));
		
			//get the IPv4 header
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
			
			//if package is ICMP ECHO REQUEST -> reply
			if(ip_hdr->daddr == inet_addr(get_interface_ip(interface)) && ip_hdr->protocol == 1) {
				struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				if(icmp_hdr->type == 8) {
					send_icmp(buf, interface, 0);
					continue;
				}
			}

			//check package integrity and drop the package if corrupted
			uint16_t initial_checksum = ip_hdr->check;
			ip_hdr->check = 0;
			if(ntohs(initial_checksum) != checksum((u_int16_t *)ip_hdr, sizeof(struct iphdr))) {
				printf("checksum err\n");
				continue;
			}

			//TTL check, if TTL expired -> send ICMP reply and drop the package
			//else update TTL and checksum
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

			//find the best route to send the package
			//if route is not found, send ICMP reply and drop the package
			struct route_table_entry *best_route = get_route(rtable, rtable_len, ip_hdr->daddr);
			if(best_route == NULL) {
				send_icmp(buf, interface, 3);
				continue;
			}
			uint8_t route_mac[HLEN];
			get_interface_mac(best_route->interface, route_mac);

			//check ARP table to find route's IP
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
				char *buf_copy = malloc(MAX_PACKET_LEN + sizeof(size_t));
				memcpy(buf_copy, &len, sizeof(size_t));
				memcpy(buf_copy + sizeof(size_t), buf, len);
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
			//entry found in ARP table -> send the packet
			else {
				memcpy(eth_hdr->ether_shost, route_mac, HLEN);
				memcpy(eth_hdr->ether_dhost, arptable[arp_index].mac, HLEN);
				send_to_link(best_route->interface, buf, len);
			}
		}
		//packet is ARP type
		else if (eth_hdr->ether_type == ETHERTYPE_ARP) {
		
			printf("TYPE: %d arp\n\n", ntohs(eth_hdr->ether_type));
		
			//get ARP HEADER
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
		
			//packet is ARP REQUEST for router's MAC -> reply
			if(arp_hdr->op == ARP_REQUEST && arp_hdr->tpa == inet_addr(get_interface_ip(interface))) {

				//update ETH HEADER
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, HLEN);
				memcpy(eth_hdr->ether_shost, mac, HLEN);

				//update ARP HEADER
				memcpy(arp_hdr->tha, arp_hdr->sha, HLEN);
				memcpy(arp_hdr->sha, mac, HLEN);
				u_int32_t aux_ip = arp_hdr->tpa;
				arp_hdr->tpa = arp_hdr->spa;
				arp_hdr->spa = aux_ip;
				arp_hdr->op = ARP_REPLY;
				
				//send back the reply
				send_to_link(interface, buf, len);
			}
			//packet is ARP REPLY -> new entry in ARP table 
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
					
					//get packet length and payload from queue
					char *packet = (char *)queue_deq(packet_q);
					size_t payload_len;
					char payload[MAX_PACKET_LEN];
					memcpy(&payload_len, packet, sizeof(size_t));
					memcpy(payload, packet + sizeof(size_t), payload_len);

					//get packet headers
					struct ether_header *pkt_eth_hdr = (struct ether_header *) payload;
					struct iphdr *pkt_ip_hdr = (struct iphdr *)(payload + sizeof(struct ether_header));

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
					send_to_link(best_route->interface, payload, payload_len);
				}
			}
		}
		//packet type is unknown
		else printf("TYPE not supported\n\n");
	}
}