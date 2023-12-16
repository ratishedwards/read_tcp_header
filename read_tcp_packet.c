#include<stdio.h>		// printf()
#include<string.h>		// memset()
#include<sys/socket.h>		// socket()
#include<netinet/in.h>		// IPPROTO_RAW
#include<unistd.h>		// close()
#include<stdlib.h>		// EXIT_FAILURE
#include<linux/if.h>		// IFNAMSIZ
#include<linux/if_ether.h>	// ETH_P_ALL
#include<arpa/inet.h>		// inet_ntop

#define BUFF_SIZE 4096

struct ETHERNET_HEADER {
	uint8_t destination_mac[6];
	uint8_t source_mac[6];
	uint16_t type;
} __attribute__((packed));

struct IP_HEADER {
	unsigned int ihl:4;
	unsigned int version:4;
	uint8_t tos;
	uint16_t tol;
	uint16_t id;
	uint16_t frag;
	uint8_t ttl;
	uint8_t proto;
	uint16_t checksum;
	uint32_t saddr;
	uint32_t daddr;
}__attribute__((packed));

struct TCP_HEADER {
	uint16_t sport;
	uint16_t dport;
	uint32_t seqno;
	uint32_t ackno;
	unsigned int res:4;
	unsigned data_offset:4;
	unsigned int fin:1;
	unsigned int syn:1;
	unsigned int rst:1;
	unsigned int psh:1;
	unsigned int ack:1;
	unsigned int urg:1;
	unsigned int ece:1;
	unsigned int cwr:1;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_pointer;
};

int main(int argc, char *argv[]){

	int sock_fd;
	int opt = 1;
	char *ifName = "wlp0s20f3";
	struct sockaddr_in saddr, daddr;
	int bytes = 0;
	uint8_t buffer[BUFF_SIZE] = {0};

	memset(&saddr, 0, sizeof(saddr));
	memset(&daddr, 0, sizeof(daddr));

	// Pointer to the ethernet header
	struct ETHERNET_HEADER *eth_header = (struct ETHERNET_HEADER *)buffer;

	// Pointer to the ip header
	struct IP_HEADER *ip_header = (struct IP_HEADER *)(buffer + sizeof(struct ETHERNET_HEADER));

	// Pointer to the tcp header
	struct TCP_HEADER *tcp_header = (struct TCP_HEADER *)(buffer + sizeof(struct ETHERNET_HEADER) + sizeof(struct IP_HEADER));

	printf("+++++++++++Program to read |Ethernet|IP|TCP| header and print it++++++++++++++++++\n");

	// To receive all IP packets, use ETH_P_IP with socket
	if ((sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
		perror("socket() error");
		exit(EXIT_FAILURE);
	}

	// Allow socket reuse
	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0){
                perror("setsockopt() error");
                exit(EXIT_FAILURE);
        }

	// Bind the socket to particular device
	if (setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ-1) < 0){
		perror("setsockopt() error");
		exit(EXIT_FAILURE);
	}

	printf("Waiting for a packet...\n");

	if ((bytes = recvfrom(sock_fd, buffer, BUFF_SIZE, 0, NULL, NULL)) < 0){
		perror("Receive Error()");
		exit(EXIT_FAILURE);
	}
	
	printf("Received packet...[%d bytes]\n", bytes);
	printf("++++++++++ETHERNET HEADER+++++++++++++++\n");
	printf("+ destination_mac : %02X:%02X:%02X:%02X:%02X:%02X\n",
                eth_header->destination_mac[0],
                eth_header->destination_mac[1],
                eth_header->destination_mac[2],
                eth_header->destination_mac[3],
                eth_header->destination_mac[4],
                eth_header->destination_mac[5]
                );
	printf("+ source_mac      : %02X:%02X:%02X:%02X:%02X:%02X\n",
		eth_header->source_mac[0],
		eth_header->source_mac[1],
		eth_header->source_mac[2],
		eth_header->source_mac[3],
		eth_header->source_mac[4],
		eth_header->source_mac[5]
		);
	printf("+ type            : %x\n",
		ntohs(eth_header->type));

	saddr.sin_addr.s_addr = ip_header->saddr;
	daddr.sin_addr.s_addr = ip_header->daddr;

	printf("++++++++++++++++++++++++++++++++++++++++\n");
	printf("++++++++++IP Header+++++++++++++++++++++\n");
	printf("+ version             : %d\n", (unsigned int)ip_header->version);
	printf("+ header length       : %d\n", (unsigned int)ip_header->ihl);
	printf("+ type of service     : %d\n", ip_header->tos);
	printf("+ total length        : %d\n", ntohs(ip_header->tol));
	printf("+ Identification      : %d\n", ntohs(ip_header->id));
	printf("+ Frag Offset         : %d\n", ip_header->frag);
	printf("+ TTL                 : %d\n", ip_header->ttl);
	printf("+ Protocol            : %d\n", ip_header->proto);
	printf("+ checksum            : %d\n", ip_header->checksum);
	printf("+ Source address      : %s\n", inet_ntoa(saddr.sin_addr));
	printf("+ Destination Address : %s\n", inet_ntoa(daddr.sin_addr));
	printf("++++++++++++++++++++++++++++++++++++++++\n");
	printf("++++++++++TCP Header++++++++++++++++++++\n");
	printf("+ Sport            : %d\n", ntohs(tcp_header->sport));
	printf("+ Dport            : %d\n", ntohs(tcp_header->dport));
	printf("+ Seqno            : %d\n", ntohs(tcp_header->seqno));
	printf("+ Ackno            : %d\n", ntohs(tcp_header->ackno));
	printf("+ Res bits         : %d\n", tcp_header->res);
	printf("+ Data Offset      : %d\n", ntohs(tcp_header->data_offset));
	printf("+ FIN              : %d\n", tcp_header->fin);
	printf("+ SYN              : %d\n", tcp_header->syn);
	printf("+ RST              : %d\n", tcp_header->rst);
	printf("+ PSH              : %d\n", tcp_header->psh);
	printf("+ ACK              : %d\n", tcp_header->ack);
	printf("+ URG              : %d\n", tcp_header->urg);
	printf("+ ECE              : %d\n", tcp_header->ece);
	printf("+ CWR              : %d\n", tcp_header->cwr);
	printf("+ Window           : %d\n", ntohs(tcp_header->window));
	printf("+ Checksum         : %d\n", ntohs(tcp_header->checksum));
	printf("+ Urgent_pointer   : %d\n", ntohs(tcp_header->urgent_pointer));
	printf("++++++++++++++++++++++++++++++++++++++++\n");

	close(sock_fd);
	return 0;
}
