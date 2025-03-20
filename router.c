#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>



struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arp_table;
int arp_table_len;

// compare function for qsort
int comparator(const void *x, const void *y) {
    const struct route_table_entry *a = (const struct route_table_entry *)x;
    const struct route_table_entry *b = (const struct route_table_entry *)y;

    // return a->prefix - b->prefix;
	return (b->mask - a->mask);
}


struct route_table_entry *get_best_route(uint32_t ip_dest) {

	// simple iteration through the routing table to get the best route

	for (int i = 0; i < rtable_len; i++) {
		if ((ip_dest & rtable[i].mask) == rtable[i].prefix) {
			return &rtable[i];
		}
	}
	return NULL;
}




// search in the arp table for the mac address of the next hop
struct arp_table_entry *get_arp_entry(uint32_t given_ip) {

	for (int i = 0; i < arp_table_len; i++) {
		struct arp_table_entry *entry = &arp_table[i];
		if (entry->ip == given_ip) {
			return entry;
		}
	}
	return NULL;
}

// function that creates an ICMP echo reply
void send_icmp_echo_reply(int interface, struct iphdr *iphdr, struct ether_header *eth_hdr, char *buf) {
	char *icmppck = malloc(sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
	// struct icmphdr *icmphdr = getICMP(buf);
	struct iphdr *newiphdr = (struct iphdr *)(icmppck + sizeof(struct ether_header));
	struct ether_header *newether = (struct ether_header *)icmppck;
	struct icmphdr *newicmp = (struct icmphdr *)(icmppck + sizeof(struct ether_header) + sizeof(struct iphdr));

	// new ether header
	memcpy(newether->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
	memcpy(newether->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));
	newether->ether_type = htons(0x0800);
	// new ip header
	memcpy(newiphdr, iphdr, sizeof(struct iphdr));

	// new icmp header
	newicmp->checksum = 0;
	newicmp->checksum = htons(checksum((uint16_t *)newicmp, sizeof(struct icmphdr)));
	newicmp->code = 0;
	newicmp->type = 0;


	// send the packet
	send_to_link(interface, icmppck, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
}


// function that creates an ICMP time exceeded and unreachable packet and sends it
char *send_icmp_time_excided_unreachable(int interface, struct iphdr *iphdr, struct ether_header *eth_hdr, uint8_t type, char *buf) {

	char *icmppck = malloc(sizeof(struct ether_header) + sizeof(iphdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(double));
	struct icmphdr *icmphdr = (struct icmphdr *)(icmppck + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmphdr->type = type;
	icmphdr->code = 0;
	icmphdr->checksum = 0;

	struct iphdr *newiphdr = (struct iphdr *)(icmppck + sizeof(struct ether_header));
	struct ether_header *newether = (struct ether_header *)icmppck;

	// new ether header
	memcpy(newether->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
	memcpy(newether->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));
	newether->ether_type = htons(0x0800);
	
	// new ip header
	memcpy(newiphdr, iphdr, sizeof(struct iphdr));
	newiphdr->protocol=1;
	newiphdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(double));
	newiphdr->check = 0;
	newiphdr->check = htons(checksum((uint16_t *)iphdr, sizeof(struct iphdr)));

	// new icmp header

	memcpy(((char*) icmphdr) + sizeof(struct icmphdr), iphdr, sizeof(struct iphdr) + sizeof(double));

	// recalculate checksum
	icmphdr->checksum = htons(checksum((uint16_t *)icmphdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(double)));
	// send the packet
	return icmppck;
}




int main(int argc, char *argv[]) {
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Parse the routing table
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "rtable_memory");

	arp_table = malloc(sizeof(struct arp_table_entry) * 100);
	DIE(arp_table == NULL, "arp_table_memory");

	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);
	// sort the routing table 
	qsort((void*)rtable, rtable_len, sizeof(struct route_table_entry), comparator);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	
		// check if the packet is an IP packet
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) { 
			// if the packet is an ICMP echo request, send an ICMP echo reply
			struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
			if (ip_hdr->protocol == 1 && icmp_hdr->type == 8) {
				send_icmp_echo_reply(interface, ip_hdr, eth_hdr, buf);
				continue;
			}

			uint16_t newcheck = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			uint16_t checkAux = checksum((uint16_t*) ip_hdr, sizeof(struct iphdr));

			if (newcheck != checkAux) {
				continue;
			}
			// if the TTL is 1, send an ICMP time exceeded packet
			if (ip_hdr->ttl <=1)
			{
				char * icmppck = send_icmp_time_excided_unreachable(interface, ip_hdr, eth_hdr, 11, buf);
				send_to_link(interface, icmppck, sizeof(struct ether_header) + sizeof(ip_hdr) + 
					sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(double));	
				continue;
			} else {
				ip_hdr->ttl--;
			}

			// seaching for the best route and if it doesn't exist, send an ICMP destination unreachable packet
			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
			if (best_route == NULL) {
				char * icmppck = send_icmp_time_excided_unreachable(interface, ip_hdr, eth_hdr, 3, buf);
				send_to_link(interface, icmppck, sizeof(struct ether_header) + sizeof(ip_hdr) + 
					sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(double));	
				continue;
			}

			// search for the mac address of the next hop
			struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);

			// update the checksum
			ip_hdr->check = 0;
			uint16_t checkAuxAfterRT = checksum((uint16_t*) ip_hdr, sizeof(struct iphdr));
			ip_hdr->check = htons(checkAuxAfterRT);

			memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(arp_entry->mac));
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			// send the packet
			send_to_link(best_route->interface, buf, len);
			
		}
		
	}
}

